/**
 *    Copyright (C) 2022-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#pragma once

#include <array>
#include <fmt/format.h>
#include <vector>

#include "mongo/base/data_range.h"
#include "mongo/base/string_data.h"

/*
 * The many token types are derived from the index key
 *
 * Terminology
 * f = field
 * v = value
 * u =
 *   - For non-contentious fields, we select the partition number, u, to be equal to 0.
 *   - For contentious fields, with a contention factor, p, we pick the partition number, u,
 * uniformly at random from the set {0, ..., p}.
 *
 * CollectionsLevel1Token = HMAC(IndexKey, 1) = K_{f,1}
 * ServerDataEncryptionLevel1Token = HMAC(IndexKey, 3) = K_{f,3} = Fs[f,3]
 *
 * EDCToken = HMAC(CollectionsLevel1Token, 1) = K^{edc}_f = Fs[f,1,1]
 * ESCToken = HMAC(CollectionsLevel1Token, 2) = K^{esc}_f = Fs[f,1,2]
 * ECOCToken = HMAC(CollectionsLevel1Token, 4) = K^{ecoc}_f = Fs[f,1,4]
 *
 * EDCDerivedFromDataToken = HMAC(EDCToken, v) = K^{edc}_{f,v} = Fs[f,1,1,v]
 * ESCDerivedFromDataToken = HMAC(ESCToken, v) = K^{esc}_{f,v} = Fs[f,1,2,v]
 *
 * EDCDerivedFromDataTokenAndContentionFactorToken = HMAC(EDCDerivedFromDataToken, u) =
 * Fs[f,1,1,v,u]
 * ESCDerivedFromDataTokenAndContentionFactorToken = HMAC(ESCDerivedFromDataToken, u) =
 * Fs[f,1,2,v,u]
 *
 * EDCTwiceDerivedToken = HMAC(EDCDerivedFromDataTokenAndContentionFactorToken, 1) = Fs_edc(1)
 * ESCTwiceDerivedTagToken = HMAC(ESCDerivedFromDataTokenAndContentionFactorToken, 1) = Fs_esc(1)
 * ESCTwiceDerivedValueToken = HMAC(ESCDerivedFromDataTokenAndContentionFactorToken, 2) = Fs_esc(2)
 *
 * ServerTokenDerivationLevel1Token = HMAC(IndexKey, 2) = K_{f,2}
 * ServerDerivedFromDataToken = HMAC(ServerTokenDerivationLevel1Token, v) = K_{f,2,v} = Fs[f,2,v]
 * ServerCountAndContentionFactorEncryptionToken = HMAC(ServerDerivedFromDataToken, 1) = Fs[f,2,v,1]
 * ServerZerosEncryptionToken = HMAC(ServerDerivedFromDataToken, 2) = Fs[f,2,v,2]
 *
 * Range Protocol V2
 * AnchorPaddingRootToken = HMAC(ESCToken, d) = S^esc_f_d = Fs[f,1,2,d]
 *  d = 136 bit blob of zero = 17 octets of 0
 * AnchorPaddingKeyToken = HMAC(AnchorPaddingRootToken, 1) = S1_d = F^(S^esc_fd)(1)
 * AnchorPaddingValueToken = HMAC(AnchorPaddingRootToken, 2) =  S2_d = F^(S^esc_fd)(2)
 */

namespace mongo {
// Forward declare to avoid including the header file.
class MongoCryptBuffer;

using PrfBlock = std::array<std::uint8_t, 32>;

// An abstract class that all tokens derive from.
// Enables reduced code for common functions in fle_crypto.
class FLEToken {
public:
    virtual ~FLEToken() {}

    virtual StringData name() const = 0;

    virtual PrfBlock asPrfBlock() const = 0;
    virtual MongoCryptBuffer asMongoCryptBuffer() const = 0;
    virtual ConstDataRange toCDR() const = 0;
};

}  // namespace mongo

#define FLE_TOKEN_TYPE_MC(TokenType) mc_##TokenType##_t
#define FLE_CRYPTO_TOKEN_FWD(TokenType) \
    typedef struct FLE_TOKEN_TYPE_MC(TokenType) FLE_TOKEN_TYPE_MC(TokenType);

// Variadic arguments represent parameters for the token's ::deriveFrom function.
#define FLE_TOKEN_DECL_CLASS(TokenType, ...)                                   \
    /* Forward declare the type name */                                        \
    FLE_CRYPTO_TOKEN_FWD(TokenType)                                            \
    namespace mongo {                                                          \
    class TokenType : public FLEToken {                                        \
    public:                                                                    \
        /* Default constructor */                                              \
        TokenType();                                                           \
                                                                               \
        /* mc_##TokenType##_t constructor */                                   \
        TokenType(FLE_TOKEN_TYPE_MC(TokenType) * token);                       \
                                                                               \
        /* Copy constructor */                                                 \
        TokenType(const TokenType& other);                                     \
                                                                               \
        /* Assignment operator */                                              \
        TokenType& operator=(const TokenType& other);                          \
                                                                               \
        /* Move constructor */                                                 \
        TokenType(TokenType&& other);                                          \
                                                                               \
        /* Move assignemnt operator */                                         \
        TokenType& operator=(TokenType&& other);                               \
                                                                               \
        /* Destructor */                                                       \
        ~TokenType() override;                                                 \
                                                                               \
        const FLE_TOKEN_TYPE_MC(TokenType) * get() const;                      \
                                                                               \
        /* Construct from a PrfBlock */                                        \
        explicit TokenType(const PrfBlock& block);                             \
                                                                               \
        PrfBlock asPrfBlock() const override;                                  \
        MongoCryptBuffer asMongoCryptBuffer() const override;                  \
        ConstDataRange toCDR() const override;                                 \
                                                                               \
        bool operator==(const TokenType& other) const;                         \
        bool operator!=(const TokenType& other) const;                         \
                                                                               \
        static TokenType parse(ConstDataRange block);                          \
        static TokenType deriveFrom(__VA_ARGS__);                              \
                                                                               \
        template <typename H>                                                  \
        friend H AbslHashValue(H h, const TokenType& token) {                  \
            return H::combine(std::move(h), token.name(), token.asPrfBlock()); \
        }                                                                      \
                                                                               \
        StringData name() const override {                                     \
            return StringData(#TokenType);                                     \
        }                                                                      \
                                                                               \
    private:                                                                   \
        FLE_TOKEN_TYPE_MC(TokenType) * _token;                                 \
                                                                               \
        void initializeFromBuffer(MongoCryptBuffer buffer);                    \
    };                                                                         \
    }

// Declare the classes by passing through the name and a variable amount of parameters that define
// how each token should be able to be derived. See the comment at the top of the file for more
// specific details.
FLE_TOKEN_DECL_CLASS(CollectionsLevel1Token, const MongoCryptBuffer& buf)
FLE_TOKEN_DECL_CLASS(ServerDataEncryptionLevel1Token, const MongoCryptBuffer& buf)

FLE_TOKEN_DECL_CLASS(EDCToken, const CollectionsLevel1Token& parent)
FLE_TOKEN_DECL_CLASS(ESCToken, const CollectionsLevel1Token& parent)
FLE_TOKEN_DECL_CLASS(ECOCToken, const CollectionsLevel1Token& parent)

FLE_TOKEN_DECL_CLASS(EDCDerivedFromDataToken, const EDCToken& parent, ConstDataRange cdr)
FLE_TOKEN_DECL_CLASS(ESCDerivedFromDataToken, const ESCToken& parent, ConstDataRange cdr)

FLE_TOKEN_DECL_CLASS(EDCDerivedFromDataTokenAndContentionFactor,
                     const EDCDerivedFromDataToken& parent,
                     std::uint64_t arg)
FLE_TOKEN_DECL_CLASS(ESCDerivedFromDataTokenAndContentionFactor,
                     const ESCDerivedFromDataToken& parent,
                     std::uint64_t arg)

FLE_TOKEN_DECL_CLASS(EDCTwiceDerivedToken, const EDCDerivedFromDataTokenAndContentionFactor& parent)
FLE_TOKEN_DECL_CLASS(ESCTwiceDerivedTagToken,
                     const ESCDerivedFromDataTokenAndContentionFactor& parent)
FLE_TOKEN_DECL_CLASS(ESCTwiceDerivedValueToken,
                     const ESCDerivedFromDataTokenAndContentionFactor& parent)

FLE_TOKEN_DECL_CLASS(ServerTokenDerivationLevel1Token, const MongoCryptBuffer& buf)
FLE_TOKEN_DECL_CLASS(ServerDerivedFromDataToken,
                     const ServerTokenDerivationLevel1Token& parent,
                     ConstDataRange cdr)
FLE_TOKEN_DECL_CLASS(ServerCountAndContentionFactorEncryptionToken,
                     const ServerDerivedFromDataToken& parent)
FLE_TOKEN_DECL_CLASS(ServerZerosEncryptionToken, const ServerDerivedFromDataToken& parent)

FLE_TOKEN_DECL_CLASS(AnchorPaddingTokenRoot, const ESCToken& parent)
FLE_TOKEN_DECL_CLASS(AnchorPaddingKeyToken, const AnchorPaddingTokenRoot& parent)
FLE_TOKEN_DECL_CLASS(AnchorPaddingValueToken, const AnchorPaddingTokenRoot& parent)

#undef FLE_TOKEN_TYPE_MC
#undef FLE_CRYPTO_TOKEN_FWD
#undef FLE_TOKEN_DECL_CLASS

namespace mongo {
// Some keys have slightly different names in the server repo compared to libmongocrypt.
using EDCDerivedFromDataTokenAndContentionFactorToken = EDCDerivedFromDataTokenAndContentionFactor;
using ESCDerivedFromDataTokenAndContentionFactorToken = ESCDerivedFromDataTokenAndContentionFactor;
using AnchorPaddingRootToken = AnchorPaddingTokenRoot;

/**
 * Values of ECOC documents in Queryable Encryption protocol version 2
 *
 * Encrypt(ECOCToken, ESCDerivedFromDataTokenAndContentionFactorToken)
 *
 * struct {
 *    uint8_t[32] esc;
 *    uint8_t isLeaf; // Optional: 0 or 1 for range operations, absent for equality.
 * }
 */
class StateCollectionTokensV2 {
public:
    StateCollectionTokensV2() = default;

    /**
     * Initialize ESCTV2 with an unencrypted payload of ESCToken and isLeaf.
     * Must call encrypt() before attempting to serialize.
     */
    StateCollectionTokensV2(ESCDerivedFromDataTokenAndContentionFactorToken s,
                            boost::optional<bool> leaf)
        : _esc(std::move(s)), _isLeaf(std::move(leaf)) {}

    /**
     * Return the ESCDerivedFromDataTokenAndContentionFactorToken value.
     */
    const ESCDerivedFromDataTokenAndContentionFactorToken&
    getESCDerivedFromDataTokenAndContentionFactorToken() const {
        return _esc;
    }

    /**
     * Returns true if the encryptedToken is an equality token, false otherwise.
     */
    bool isEquality() const {
        return getIsLeaf() == boost::none;
    }

    /**
     * Returns true if the encryptedToken is a range token, false otherwise.
     */
    bool isRange() const {
        return getIsLeaf() != boost::none;
    }

    /**
     * Returns the trinary value isLeaf indicating equality(none), range-leaf(true), or
     * range-nonleaf(false).
     */
    boost::optional<bool> getIsLeaf() const {
        return _isLeaf;
    }

    /**
     * StateCollectionTokensV2 serialized into a packed structure and encrypted.
     */
    class Encrypted {
    public:
        Encrypted() = default;
        explicit Encrypted(std::vector<std::uint8_t> encryptedTokens)
            : _encryptedTokens(std::move(encryptedTokens)) {
            assertLength(_encryptedTokens.size());
        }

        static Encrypted parse(ConstDataRange encryptedTokens) {
            std::vector<std::uint8_t> ret;
            const auto* src = encryptedTokens.data<std::uint8_t>();
            std::copy(src, src + encryptedTokens.length(), std::back_inserter(ret));
            return Encrypted(std::move(ret));
        }

        /**
         * Serialize the encrypted payload to a CDR.
         */
        ConstDataRange toCDR() const {
            // Assert length on serialization to ensure we're not serializing a default object.
            assertLength(_encryptedTokens.size());
            return {_encryptedTokens.data(), _encryptedTokens.size()};
        }

        /**
         * Generate a BSON document consisting of:
         * {
         *   "_id": OID::gen(),
         *   "fieldName": {fieldName},
         *   "value": {encryptedTokens},
         * }
         */
        BSONObj generateDocument(StringData fieldName) const;

        /**
         * Decrypt _encryptedTokens back to esc/isLeaf using ECOCToken.
         */
        StateCollectionTokensV2 decrypt(const ECOCToken& token) const;

    private:
        // Encrypted payloads should be 48 or 49 bytes in length.
        // IV(16) + PrfBlock(32) + optional-range-flag(1)
        static constexpr std::size_t kCTRIVSize = 16;
        static constexpr std::size_t kCipherLengthESCOnly = kCTRIVSize + sizeof(PrfBlock);
        static constexpr std::size_t kCipherLengthESCAndLeafFlag = kCipherLengthESCOnly + 1;

        static void assertLength(std::size_t sz) {
            using namespace fmt::literals;
            uassert(
                ErrorCodes::BadValue,
                "Invalid length for EncryptedStateCollectionTokensV2, expected {} or {}, got {}"_format(
                    sizeof(PrfBlock), sizeof(PrfBlock) + 1, sz),
                (sz == kCipherLengthESCOnly) || (sz == kCipherLengthESCAndLeafFlag));
        }

        std::vector<std::uint8_t> _encryptedTokens;
    };

    /**
     * Encrypt _esc/_isLeaf and using ECOCToken.
     */
    Encrypted encrypt(const ECOCToken& token) const;

private:
    ESCDerivedFromDataTokenAndContentionFactorToken _esc;
    boost::optional<bool> _isLeaf;
};

}  // namespace mongo