/*
 * Copyright (c) 2026 Project CHIP Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#include "MatterCredentials.h"

#include <json/json.h>
#include <lib/core/TLV.h>
#include <lib/support/Base64.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/logging/CHIPLogging.h>

#include <algorithm>
#include <fstream>
#include <limits>
#include <utility>

namespace {

using namespace chip;

bool IsBase64(const std::string & value)
{
    if (value.empty() || value.size() % 4 != 0)
    {
        return false;
    }

    const size_t padding = (value.back() == '=') + (value.size() > 1 && value[value.size() - 2] == '=');
    for (size_t index = 0; index < value.size(); ++index)
    {
        const char character = value[index];
        const bool isData    = (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') || character == '+' || character == '/';
        if (index < value.size() - padding ? !isData : character != '=')
        {
            return false;
        }
    }
    return true;
}

CHIP_ERROR ReadBase64Field(const Json::Value & root, const char * field, std::vector<uint8_t> & output, size_t maxSize,
                           size_t expectedSize = 0)
{
    VerifyOrReturnError(root.isMember(field) && root[field].isString(), CHIP_ERROR_INVALID_ARGUMENT,
                        ChipLogError(chipTool, "Credential manifest requires string field '%s'", field));

    const std::string encoded = root[field].asString();
    VerifyOrReturnError(IsBase64(encoded) && encoded.size() <= BASE64_ENCODED_LEN(maxSize), CHIP_ERROR_INVALID_ARGUMENT,
                        ChipLogError(chipTool, "Credential field '%s' is not valid padded Base64", field));

    output.resize(BASE64_MAX_DECODED_LEN(encoded.size()));
    const uint32_t decodedSize = chip::Base64Decode32(encoded.data(), static_cast<uint32_t>(encoded.size()), output.data());
    VerifyOrReturnError(decodedSize != std::numeric_limits<uint32_t>::max() && decodedSize > 0 && decodedSize <= maxSize,
                        CHIP_ERROR_INVALID_ARGUMENT,
                        ChipLogError(chipTool, "Credential field '%s' is not valid Base64", field));
    output.resize(decodedSize);

    VerifyOrReturnError(expectedSize == 0 || decodedSize == expectedSize, CHIP_ERROR_INVALID_ARGUMENT,
                        ChipLogError(chipTool, "Credential field '%s' must decode to %u bytes", field,
                                     static_cast<unsigned>(expectedSize)));
    return CHIP_NO_ERROR;
}

CHIP_ERROR ReadCertificateField(const Json::Value & root, const char * field, std::vector<uint8_t> & x509Certificate)
{
    std::vector<uint8_t> encodedCertificate;
    ReturnErrorOnFailure(ReadBase64Field(root, field, encodedCertificate, chip::Controller::kMaxCHIPDERCertLength));

    if (encodedCertificate.front() == 0x30) // X.509 certificates start with an ASN.1 SEQUENCE.
    {
        uint8_t chipCertificateBuffer[chip::Credentials::kMaxCHIPCertLength];
        chip::MutableByteSpan chipCertificate(chipCertificateBuffer);
        ReturnErrorOnFailure(chip::Credentials::ConvertX509CertToChipCert(chip::ByteSpan(encodedCertificate.data(),
                                                                                        encodedCertificate.size()),
                                                                         chipCertificate));
        x509Certificate = std::move(encodedCertificate);
        return CHIP_NO_ERROR;
    }

    x509Certificate.resize(chip::Controller::kMaxCHIPDERCertLength);
    chip::MutableByteSpan x509Span(x509Certificate.data(), x509Certificate.size());
    ReturnErrorOnFailure(chip::Credentials::ConvertChipCertToX509Cert(
        chip::ByteSpan(encodedCertificate.data(), encodedCertificate.size()), x509Span));
    x509Certificate.resize(x509Span.size());
    return CHIP_NO_ERROR;
}

CHIP_ERROR CopyToMutableSpan(ByteSpan source, MutableByteSpan & destination)
{
    VerifyOrReturnError(source.size() <= destination.size(), CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(destination.data(), source.data(), source.size());
    destination.reduce_size(source.size());
    return CHIP_NO_ERROR;
}

} // namespace

CHIP_ERROR MatterCredentialConfig::Load(const char * manifestPath)
{
    VerifyOrReturnError(manifestPath != nullptr, CHIP_ERROR_INVALID_ARGUMENT);

    std::ifstream stream(manifestPath);
    VerifyOrReturnError(stream.is_open(), CHIP_ERROR_OPEN_FAILED,
                        ChipLogError(chipTool, "Unable to open credential manifest: %s", manifestPath));

    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errors;
    VerifyOrReturnError(Json::parseFromStream(builder, stream, &root, &errors), CHIP_ERROR_INVALID_ARGUMENT,
                        ChipLogError(chipTool, "Invalid credential manifest: %s", errors.c_str()));

    VerifyOrReturnError(root.isMember("mode") && root["mode"].isString(), CHIP_ERROR_INVALID_ARGUMENT,
                        ChipLogError(chipTool, "Credential manifest requires string field 'mode'"));

    const std::string mode = root["mode"].asString();
    if (mode == "noc")
    {
        mMode = MatterCredentialMode::kNOC;
    }
    else if (mode == "icac")
    {
        mMode = MatterCredentialMode::kICAC;
    }
    else
    {
        ChipLogError(chipTool, "Credential mode must be 'noc' or 'icac'");
        return CHIP_ERROR_INVALID_ARGUMENT;
    }

    ReturnErrorOnFailure(ReadCertificateField(root, "rcac", mRCAC));
    ReturnErrorOnFailure(ReadCertificateField(root, "icac", mICAC));
    ReturnErrorOnFailure(ReadBase64Field(root, "ipk", mIPK, Crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES,
                                         Crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES));

    const char * publicKeyField  = mMode == MatterCredentialMode::kNOC ? "operational_public_key" : "icac_public_key";
    const char * privateKeyField = mMode == MatterCredentialMode::kNOC ? "operational_private_key" : "icac_private_key";
    ReturnErrorOnFailure(
        ReadBase64Field(root, publicKeyField, mPublicKey, Crypto::kP256_PublicKey_Length, Crypto::kP256_PublicKey_Length));
    ReturnErrorOnFailure(
        ReadBase64Field(root, privateKeyField, mPrivateKey, Crypto::kP256_PrivateKey_Length, Crypto::kP256_PrivateKey_Length));

    if (mMode == MatterCredentialMode::kNOC)
    {
        ReturnErrorOnFailure(ReadCertificateField(root, "noc", mNOC));
    }

    VerifyOrReturnError(mRCAC.size() <= Controller::kMaxCHIPDERCertLength &&
                            mICAC.size() <= Controller::kMaxCHIPDERCertLength &&
                            mNOC.size() <= Controller::kMaxCHIPDERCertLength,
                        CHIP_ERROR_INVALID_ARGUMENT, ChipLogError(chipTool, "A certificate exceeds the Matter DER size limit"));

    ChipLogProgress(chipTool, "Loaded chip-exp credential manifest in %s mode", mode.c_str());
    return CHIP_NO_ERROR;
}

CHIP_ERROR ConfiguredOperationalCredentialsIssuer::Configure(const MatterCredentialConfig & config)
{
    VerifyOrReturnError(config.GetMode() == MatterCredentialMode::kICAC, CHIP_ERROR_INVALID_ARGUMENT);

    mICACKeypair.Clear();
    ReturnErrorOnFailure(mICACKeypair.HazardousOperationLoadKeypairFromRaw(config.GetPrivateKey(), config.GetPublicKey()));

    Crypto::P256PublicKey certificatePublicKey;
    ReturnErrorOnFailure(Crypto::ExtractPubkeyFromX509Cert(config.GetICAC(), certificatePublicKey));
    VerifyOrReturnError(mICACKeypair.Pubkey().Matches(certificatePublicKey), CHIP_ERROR_INVALID_PUBLIC_KEY,
                        ChipLogError(chipTool, "The ICAC private key does not match the ICAC certificate"));

    mRCAC.assign(config.GetRCAC().begin(), config.GetRCAC().end());
    mICAC.assign(config.GetICAC().begin(), config.GetICAC().end());
    std::copy(config.GetIPK().begin(), config.GetIPK().end(), mIPK.begin());

    mIssuerDN = Credentials::ChipDN{};
    ReturnErrorOnFailure(Credentials::ExtractSubjectDNFromX509Cert(config.GetICAC(), mIssuerDN));
    Credentials::CertType issuerType;
    ReturnErrorOnFailure(mIssuerDN.GetCertType(issuerType));
    VerifyOrReturnError(issuerType == Credentials::CertType::kICA, CHIP_ERROR_WRONG_CERT_TYPE,
                        ChipLogError(chipTool, "Configured issuer certificate is not an ICAC"));

    uint8_t chipCertBuffer[Credentials::kMaxCHIPCertLength];
    MutableByteSpan chipCert(chipCertBuffer);
    ReturnErrorOnFailure(Credentials::ConvertX509CertToChipCert(config.GetICAC(), chipCert));
    Credentials::ChipCertificateData certificateData;
    ReturnErrorOnFailure(Credentials::DecodeChipCert(chipCert, certificateData));
    mValidityStart = certificateData.mNotBeforeTime;
    mValidityEnd   = certificateData.mNotAfterTime;
    mConfigured    = true;

    ChipLogProgress(chipTool, "Configured ICAC-backed NOC issuer");
    return CHIP_NO_ERROR;
}

CHIP_ERROR ConfiguredOperationalCredentialsIssuer::IssueNOC(NodeId nodeId, FabricId fabricId, const CATValues & cats,
                                                            const Crypto::P256PublicKey & publicKey, MutableByteSpan & noc)
{
    VerifyOrReturnError(mConfigured, CHIP_ERROR_INCORRECT_STATE);
    VerifyOrReturnError(IsOperationalNodeId(nodeId) && IsValidFabricId(fabricId), CHIP_ERROR_INVALID_ARGUMENT);

    Credentials::ChipDN subjectDN;
    ReturnErrorOnFailure(subjectDN.AddAttribute_MatterFabricId(fabricId));
    ReturnErrorOnFailure(subjectDN.AddAttribute_MatterNodeId(nodeId));
    ReturnErrorOnFailure(subjectDN.AddCATs(cats));

    Credentials::X509CertRequestParams request = { mSerialNumber++, mValidityStart, mValidityEnd, subjectDN, mIssuerDN };
    ChipLogProgress(chipTool, "Issuing NOC for node 0x" ChipLogFormatX64 ", fabric 0x" ChipLogFormatX64,
                    ChipLogValueX64(nodeId), ChipLogValueX64(fabricId));
    return Credentials::NewNodeOperationalX509Cert(request, publicKey, mICACKeypair, noc);
}

CHIP_ERROR ConfiguredOperationalCredentialsIssuer::GenerateNOCChainAfterValidation(
    NodeId nodeId, FabricId fabricId, const CATValues & cats, const Crypto::P256PublicKey & publicKey, MutableByteSpan & rcac,
    MutableByteSpan & icac, MutableByteSpan & noc)
{
    ReturnErrorOnFailure(CopyToMutableSpan(ByteSpan(mRCAC.data(), mRCAC.size()), rcac));
    ReturnErrorOnFailure(CopyToMutableSpan(ByteSpan(mICAC.data(), mICAC.size()), icac));
    return IssueNOC(nodeId, fabricId, cats, publicKey, noc);
}

CHIP_ERROR ConfiguredOperationalCredentialsIssuer::GenerateNOCChain(
    const ByteSpan & csrElements, const ByteSpan & csrNonce, const ByteSpan & attestationSignature,
    const ByteSpan & attestationChallenge, const ByteSpan & DAC, const ByteSpan & PAI,
    Callback::Callback<Controller::OnNOCChainGeneration> * onCompletion)
{
    VerifyOrReturnError(mConfigured && onCompletion != nullptr, CHIP_ERROR_INCORRECT_STATE);
    (void) csrNonce;
    (void) attestationSignature;
    (void) attestationChallenge;
    (void) DAC;
    (void) PAI;

    TLV::TLVReader reader;
    reader.Init(csrElements);
    if (reader.GetType() == TLV::kTLVType_NotSpecified)
    {
        ReturnErrorOnFailure(reader.Next());
    }
    ReturnErrorOnFailure(reader.Expect(TLV::kTLVType_Structure, TLV::AnonymousTag()));

    TLV::TLVType containerType;
    ReturnErrorOnFailure(reader.EnterContainer(containerType));
    ReturnErrorOnFailure(reader.Next(TLV::kTLVType_ByteString, TLV::ContextTag(1)));
    ByteSpan csr(reader.GetReadPoint(), reader.GetLength());
    ReturnErrorOnFailure(reader.ExitContainer(containerType));

    Crypto::P256PublicKey publicKey;
    ReturnErrorOnFailure(Crypto::VerifyCertificateSigningRequest(csr.data(), csr.size(), publicKey));

    uint8_t nocBuffer[Controller::kMaxCHIPDERCertLength];
    MutableByteSpan noc(nocBuffer);
    ReturnErrorOnFailure(IssueNOC(mNodeId, mFabricId, mCATs, publicKey, noc));

    const ByteSpan icac(mICAC.data(), mICAC.size());
    const ByteSpan rcac(mRCAC.data(), mRCAC.size());
    Crypto::IdentityProtectionKeySpan ipk(mIPK.data());
    onCompletion->mCall(onCompletion->mContext, CHIP_NO_ERROR, noc, icac, rcac, MakeOptional(ipk), Optional<NodeId>());
    return CHIP_NO_ERROR;
}
