// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

import {TokenRouter} from "./libs/TokenRouter.sol";
import {HypERC20Collateral} from "./HypERC20Collateral.sol";
import {IMessageTransmitter} from "../interfaces/cctp/IMessageTransmitter.sol";
import {IInterchainSecurityModule} from "../interfaces/IInterchainSecurityModule.sol";
import {AbstractCcipReadIsm} from "../isms/ccip-read/AbstractCcipReadIsm.sol";
import {TypedMemView} from "../libs/TypedMemView.sol";
import {ITokenMessenger} from "../interfaces/cctp/ITokenMessenger.sol";
import {ITokenMessengerV2} from "../interfaces/cctp/ITokenMessengerV2.sol";
import {Message} from "../libs/Message.sol";
import {TokenMessage} from "./libs/TokenMessage.sol";
import {CctpMessage, BurnMessage} from "../libs/CctpMessage.sol";
import {CctpMessageV2} from "../libs/CctpMessageV2.sol";

interface CctpService {
    function getCCTPAttestation(
        bytes calldata _message
    ) external view returns (bytes memory cctpMessage, bytes memory attestation);
}

// TokenMessage.metadata length for CCTP v1 is 8 bytes (nonce)
uint256 constant CCTP_TOKEN_BRIDGE_MESSAGE_LEN_V1 =
    TokenMessage.METADATA_OFFSET + 8;
// For CCTP v2 there is no metadata
uint256 constant CCTP_TOKEN_BRIDGE_MESSAGE_LEN_V2 = TokenMessage.METADATA_OFFSET;

/**
 * @dev Base contract with common logic for both CCTP versions.
 */
abstract contract TokenBridgeCctp is HypERC20Collateral, AbstractCcipReadIsm {
    using CctpMessage for bytes29;
    using BurnMessage for bytes29;

    using Message for bytes;

    // CCTP message transmitter
    IMessageTransmitter public immutable messageTransmitter;

    // Address of the token messenger (v1 or v2)
    address public immutable tokenMessenger;

    struct Domain {
        uint32 hyperlane;
        uint32 circle;
    }

    /// @notice Hyperlane domain => Circle domain mapping
    mapping(uint32 hypDomain => Domain circleDomain) internal _domainMap;

    /**
     * @notice Emitted when the Hyperlane domain to Circle domain mapping is updated.
     */
    event DomainAdded(uint32 indexed hyperlaneDomain, uint32 circleDomain);

    constructor(
        address _erc20,
        uint256 _scale,
        address _mailbox,
        IMessageTransmitter _messageTransmitter,
        address _tokenMessenger
    ) HypERC20Collateral(_erc20, _scale, _mailbox) {
        messageTransmitter = _messageTransmitter;
        tokenMessenger = _tokenMessenger;
        _disableInitializers();
    }

    function initialize(
        address _hook,
        address _owner,
        string[] memory __urls
    ) external virtual initializer {
        __Ownable_init();
        setUrls(__urls);
        // ISM should not be set
        _MailboxClient_initialize(_hook, address(0), _owner);
        wrappedToken.approve(address(tokenMessenger), type(uint256).max);
    }

    // Disallow parent initialize
    function initialize(
        address,
        address,
        address
    ) public override {
        revert("Only TokenBridgeCctp.initialize() may be called");
    }

    function interchainSecurityModule()
        external
        view
        override
        returns (IInterchainSecurityModule)
    {
        return IInterchainSecurityModule(address(this));
    }

    // ----- Domain management -----

    function addDomain(uint32 _hyperlaneDomain, uint32 _circleDomain) public onlyOwner {
        _domainMap[_hyperlaneDomain] = Domain(_hyperlaneDomain, _circleDomain);
        emit DomainAdded(_hyperlaneDomain, _circleDomain);
    }

    function addDomains(Domain[] memory domains) external onlyOwner {
        for (uint32 i = 0; i < domains.length; i++) {
            addDomain(domains[i].hyperlane, domains[i].circle);
        }
    }

    function hyperlaneDomainToCircleDomain(uint32 _hyperlaneDomain) public view returns (uint32) {
        Domain memory domain = _domainMap[_hyperlaneDomain];
        require(domain.hyperlane == _hyperlaneDomain, "Circle domain not configured");
        return domain.circle;
    }

    // ----- Verification -----

    function verify(bytes calldata _metadata, bytes calldata _hyperlaneMessage) external returns (bool) {
        (bytes memory cctpMessage, bytes memory attestation) = abi.decode(_metadata, (bytes, bytes));

        bytes calldata tokenMessage = _hyperlaneMessage.body();
        _validateMessageLength(tokenMessage);

        bytes29 originalMsg = TypedMemView.ref(cctpMessage, 0);
        bytes29 burnMessage = originalMsg._messageBody();

        require(TokenMessage.amount(tokenMessage) == burnMessage._getAmount(), "Invalid amount");
        require(
            TokenMessage.recipient(tokenMessage) == burnMessage._getMintRecipient(),
            "Invalid recipient"
        );

        bytes32 sourceSender = burnMessage._getMessageSender();
        require(sourceSender == _hyperlaneMessage.sender(), "Invalid sender");

        uint32 sourceDomain = originalMsg._sourceDomain();
        require(
            sourceDomain == hyperlaneDomainToCircleDomain(_hyperlaneMessage.origin()),
            "Invalid source domain"
        );

        _maybeReceive(originalMsg, sourceDomain, tokenMessage, cctpMessage, attestation);
        return true;
    }

    // ----- Internal helpers to be implemented by versions -----

    function _maybeReceive(
        bytes29 originalMsg,
        uint32 sourceDomain,
        bytes calldata tokenMessage,
        bytes memory cctpMessage,
        bytes memory attestation
    ) internal virtual;

    function _depositForBurn(
        uint256 amount,
        uint32 circleDomain,
        bytes32 recipient,
        uint256 outboundAmount
    ) internal virtual returns (bytes memory);

    function _validateMessageLength(bytes memory _tokenMessage) internal view virtual;

    // ----- Sending tokens -----

    function _transferRemote(
        uint32 _destination,
        bytes32 _recipient,
        uint256 _amount,
        uint256 _value,
        bytes memory _hookMetadata,
        address _hook
    ) internal virtual override returns (bytes32 messageId) {
        HypERC20Collateral._transferFromSender(_amount);

        uint32 circleDomain = hyperlaneDomainToCircleDomain(_destination);
        uint256 outboundAmount = _outboundAmount(_amount);
        bytes memory _tokenMessage = _depositForBurn(
            _amount,
            circleDomain,
            _recipient,
            outboundAmount
        );

        _validateMessageLength(_tokenMessage);

        messageId = _Router_dispatch(
            _destination,
            _value,
            _tokenMessage,
            _hookMetadata,
            _hook
        );

        emit SentTransferRemote(_destination, _recipient, outboundAmount);
    }

    // ----- Offchain lookup & token receive -----

    function _offchainLookupCalldata(bytes calldata _message)
        internal
        pure
        override
        returns (bytes memory)
    {
        return abi.encodeCall(CctpService.getCCTPAttestation, (_message));
    }

    function _transferTo(address, uint256, bytes calldata) internal override {
        // do not transfer to recipient as the CCTP transfer will do it
    }
}

// ---------------------------------------------------------------------------
//                                CCTP V1
// ---------------------------------------------------------------------------

contract TokenBridgeCctpV1 is TokenBridgeCctp {
    using CctpMessage for bytes29;

    uint32 internal constant CCTP_VERSION = 0;

    constructor(
        address _erc20,
        uint256 _scale,
        address _mailbox,
        IMessageTransmitter _messageTransmitter,
        ITokenMessenger _tokenMessenger
    ) TokenBridgeCctp(_erc20, _scale, _mailbox, _messageTransmitter, address(_tokenMessenger)) {
        require(_messageTransmitter.version() == CCTP_VERSION, "Invalid messageTransmitter CCTP version");
        require(_tokenMessenger.messageBodyVersion() == CCTP_VERSION, "Invalid TokenMessenger CCTP version");
    }

    function _depositForBurn(
        uint256 amount,
        uint32 circleDomain,
        bytes32 recipient,
        uint256 outboundAmount
    ) internal override returns (bytes memory) {
        uint64 nonce = ITokenMessenger(tokenMessenger).depositForBurn(
            amount,
            circleDomain,
            recipient,
            address(wrappedToken)
        );
        return TokenMessage.format(recipient, outboundAmount, abi.encodePacked(nonce));
    }

    function _validateMessageLength(bytes memory _tokenMessage) internal view override {
        require(_tokenMessage.length == CCTP_TOKEN_BRIDGE_MESSAGE_LEN_V1, "Invalid message body length");
    }

    function _maybeReceive(
        bytes29 originalMsg,
        uint32 sourceDomain,
        bytes calldata tokenMessage,
        bytes memory cctpMessage,
        bytes memory attestation
    ) internal override {
        uint64 sourceNonce = originalMsg._nonce();
        require(sourceNonce == uint64(bytes8(TokenMessage.metadata(tokenMessage))), "Invalid nonce");
        bytes32 sourceAndNonceHash = keccak256(abi.encodePacked(sourceDomain, sourceNonce));
        if (messageTransmitter.usedNonces(sourceAndNonceHash) == 0) {
            messageTransmitter.receiveMessage(cctpMessage, attestation);
        }
    }
}

// ---------------------------------------------------------------------------
//                                CCTP V2
// ---------------------------------------------------------------------------

contract TokenBridgeCctpV2 is TokenBridgeCctp {
    uint32 internal constant CCTP_VERSION = 1;

    constructor(
        address _erc20,
        uint256 _scale,
        address _mailbox,
        IMessageTransmitter _messageTransmitter,
        ITokenMessengerV2 _tokenMessenger
    ) TokenBridgeCctp(_erc20, _scale, _mailbox, _messageTransmitter, address(_tokenMessenger)) {
        require(_messageTransmitter.version() == CCTP_VERSION, "Invalid messageTransmitter CCTP version");
        require(_tokenMessenger.messageBodyVersion() == CCTP_VERSION, "Invalid TokenMessenger CCTP version");
    }

    function _depositForBurn(
        uint256 amount,
        uint32 circleDomain,
        bytes32 recipient,
        uint256 outboundAmount
    ) internal override returns (bytes memory) {
        ITokenMessengerV2(tokenMessenger).depositForBurn(
            amount,
            circleDomain,
            recipient,
            address(wrappedToken),
            bytes32(0),
            0,
            0
        );
        return TokenMessage.format(recipient, outboundAmount);
    }

    function _validateMessageLength(bytes memory _tokenMessage) internal view override {
        require(_tokenMessage.length == CCTP_TOKEN_BRIDGE_MESSAGE_LEN_V2, "Invalid message body length");
    }

    function _maybeReceive(
        bytes29 originalMsg,
        uint32,
        bytes calldata,
        bytes memory cctpMessage,
        bytes memory attestation
    ) internal override {
        bytes32 nonceId = CctpMessageV2._getNonce(originalMsg);
        if (messageTransmitter.usedNonces(nonceId) == 0) {
            messageTransmitter.receiveMessage(cctpMessage, attestation);
        }
    }
}

