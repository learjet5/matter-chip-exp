/*
 * Copyright (c) 2026 Project CHIP Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

#pragma once

#include <controller/OperationalCredentialsDelegate.h>
#include <credentials/CHIPCert.h>
#include <credentials/GroupDataProviderImpl.h>
#include <crypto/CHIPCryptoPAL.h>
#include <lib/core/CASEAuthTag.h>
#include <lib/core/CHIPError.h>
#include <lib/support/Span.h>

#include <array>
#include <map>
#include <string>
#include <vector>

enum class MatterCredentialMode
{
    kDefault,
    kNOC,
    kICAC,
};

enum class MatterIPKType
{
    kNone,
    kEpoch,
    kOperational,
};

CHIP_ERROR NormalizeCATValue(uint64_t value, chip::CASEAuthTag & cat);

/** Credentials embedded in a chip-exp JSON manifest. */
class MatterCredentialConfig
{
public:
    CHIP_ERROR Load(const char * manifestPath);

    MatterCredentialMode GetMode() const { return mMode; }
    chip::ByteSpan GetRCAC() const { return chip::ByteSpan(mRCAC.data(), mRCAC.size()); }
    chip::ByteSpan GetICAC() const { return chip::ByteSpan(mICAC.data(), mICAC.size()); }
    chip::ByteSpan GetNOC() const { return chip::ByteSpan(mNOC.data(), mNOC.size()); }
    chip::ByteSpan GetPublicKey() const { return chip::ByteSpan(mPublicKey.data(), mPublicKey.size()); }
    chip::ByteSpan GetPrivateKey() const { return chip::ByteSpan(mPrivateKey.data(), mPrivateKey.size()); }
    MatterIPKType GetIPKType() const { return mIPKType; }
    chip::ByteSpan GetIPK() const { return chip::ByteSpan(mIPK.data(), mIPK.size()); }
    chip::FabricId GetFabricId() const { return mFabricId; }
    chip::NodeId GetControllerNodeId() const { return mControllerNodeId; }
    const chip::CATValues & GetControllerCATs() const { return mControllerCATs; }

private:
    MatterCredentialMode mMode = MatterCredentialMode::kDefault;
    std::vector<uint8_t> mRCAC;
    std::vector<uint8_t> mICAC;
    std::vector<uint8_t> mNOC;
    std::vector<uint8_t> mPublicKey;
    std::vector<uint8_t> mPrivateKey;
    MatterIPKType mIPKType = MatterIPKType::kNone;
    std::vector<uint8_t> mIPK;
    chip::FabricId mFabricId       = chip::kUndefinedFabricId;
    chip::NodeId mControllerNodeId = chip::kUndefinedNodeId;
    chip::CATValues mControllerCATs = chip::kUndefinedCATs;
};

/** Extends the stock provider with direct operational-IPK injection for imported fabrics. */
class ChipExpGroupDataProvider : public chip::Credentials::GroupDataProviderImpl
{
public:
    using GroupDataProviderImpl::GroupDataProviderImpl;

    CHIP_ERROR SetSingleOperationalIpk(chip::FabricIndex fabricIndex, chip::ByteSpan operationalIpk);
    void ClearOperationalIpk(chip::FabricIndex fabricIndex);
    CHIP_ERROR GetIpkKeySet(chip::FabricIndex fabricIndex, KeySet & outKeySet) override;
    CHIP_ERROR RemoveFabric(chip::FabricIndex fabricIndex) override;
    void Finish() override;

private:
    std::map<chip::FabricIndex, std::array<uint8_t, chip::Crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES>> mOperationalIpks;
};

/** Signs NOCs with an imported ICAC key while leaving the SDK unchanged. */
class ConfiguredOperationalCredentialsIssuer : public chip::Controller::OperationalCredentialsDelegate
{
public:
    CHIP_ERROR Configure(const MatterCredentialConfig & config);

    CHIP_ERROR GenerateNOCChain(const chip::ByteSpan & csrElements, const chip::ByteSpan & csrNonce,
                                const chip::ByteSpan & attestationSignature, const chip::ByteSpan & attestationChallenge,
                                const chip::ByteSpan & DAC, const chip::ByteSpan & PAI,
                                chip::Callback::Callback<chip::Controller::OnNOCChainGeneration> * onCompletion) override;

    void SetNodeIdForNextNOCRequest(chip::NodeId nodeId) override { mNodeId = nodeId; }
    void SetFabricIdForNextNOCRequest(chip::FabricId fabricId) override { mFabricId = fabricId; }
    void SetTargetCATValues(chip::CATValues cats) { mTargetCATs = cats; }

    CHIP_ERROR GenerateNOCChainAfterValidation(chip::NodeId nodeId, chip::FabricId fabricId, const chip::CATValues & cats,
                                               const chip::Crypto::P256PublicKey & publicKey,
                                               chip::MutableByteSpan & rcac, chip::MutableByteSpan & icac,
                                               chip::MutableByteSpan & noc);

private:
    CHIP_ERROR IssueNOC(chip::NodeId nodeId, chip::FabricId fabricId, const chip::CATValues & cats,
                        const chip::Crypto::P256PublicKey & publicKey, chip::MutableByteSpan & noc);

    chip::Crypto::P256Keypair mICACKeypair;
    std::vector<uint8_t> mRCAC;
    std::vector<uint8_t> mICAC;
    std::array<uint8_t, chip::Crypto::CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES> mIPK{};
    chip::Credentials::ChipDN mIssuerDN;
    uint32_t mValidityStart = 0;
    uint32_t mValidityEnd   = 0;
    chip::NodeId mNodeId    = 1;
    chip::FabricId mFabricId = 1;
    chip::CATValues mTargetCATs = chip::kUndefinedCATs;
    int64_t mSerialNumber    = 1;
    bool mConfigured         = false;
    bool mHasEpochIPK        = false;
};
