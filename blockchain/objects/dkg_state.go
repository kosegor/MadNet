package objects

import (
	"encoding/json"
	"errors"
	"math/big"
	"sync"

	"github.com/MadBase/MadNet/blockchain/dkg"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
)

// ErrCanNotContinue standard error if we must drop out of ETHDKG
var (
	ErrCanNotContinue = errors.New("can not continue distributed key generation")
)

// DkgState is used to track the state of the ETHDKG
type DkgState struct {
	sync.RWMutex

	isValidator        bool
	phase              EthDKGPhase
	phaseLength        uint64
	confirmationLength uint64
	phaseStart         uint64
	mpkSetAtBlock      uint64
	completionAtBlock  uint64

	// Local validator info
	////////////////////////////////////////////////////////////////////////////
	// Account is the Ethereum account corresponding to the Ethereum Public Key
	// of the local Validator
	account accounts.Account
	// Index is the Base-1 index of the local Validator which is used
	// during the Share Distribution phase for verifiable secret sharing.
	// REPEAT: THIS IS BASE-1
	index int
	// ValidatorAddresses stores all validator addresses at the beginning of ETHDKG
	validatorAddresses []common.Address
	// NumberOfValidators is equal to len(ValidatorAddresses)
	numberOfValidators int
	// ETHDKG nonce
	nonce uint64
	// ValidatorThreshold is the threshold number of validators for the system.
	// If n = NumberOfValidators and t = threshold, then
	// 			t+1 > 2*n/3
	validatorThreshold int
	// TransportPrivateKey is the private key corresponding to TransportPublicKey.
	transportPrivateKey *big.Int
	// TransportPublicKey is the public key used in EthDKG.
	// This public key is used for secret communication over the open channel
	// of Ethereum.
	transportPublicKey [2]*big.Int
	// SecretValue is the secret value which is to be shared during
	// the verifiable secret sharing.
	// The sum of all the secret values of all the participants
	// is the master secret key, the secret key of the master public key
	// (MasterPublicKey)
	secretValue *big.Int
	// PrivateCoefficients is the private polynomial which is used to share
	// the shared secret. This is performed via Shamir Secret Sharing.
	privateCoefficients []*big.Int
	// MasterPublicKey is the public key for the entire group.
	// As mentioned above, the secret key called the master secret key
	// and is the sum of all the shared secrets of all the participants.
	masterPublicKey [4]*big.Int
	// GroupPrivateKey is the local Validator's portion of the master secret key.
	// This is also denoted gskj.
	groupPrivateKey *big.Int

	// Remote validator info
	////////////////////////////////////////////////////////////////////////////
	// Participants is the list of Validators
	participants map[common.Address]*Participant // Index, Address & PublicKey

	// Share Dispute Phase
	//////////////////////////////////////////////////
	// These are the participants with bad shares
	badShares map[common.Address]*Participant

	// Group Public Key (GPKj) Accusation Phase
	//////////////////////////////////////////////////
	// DishonestValidatorsIndices stores the list indices of dishonest
	// validators
	dishonestValidators ParticipantList // Calculated for group accusation
	// HonestValidatorsIndices stores the list indices of honest
	// validators
	honestValidators ParticipantList // "
	// Inverse stores the multiplicative inverses
	// of elements. This may be used in GPKJGroupAccusation logic.
	inverse []*big.Int // "
}

// GetIsValidator returns isValidator value
func (state *DkgState) GetIsValidator() bool {
	state.RLock()
	defer state.RUnlock()

	return state.isValidator
}

// SetIsValidator updates isValidator value
func (state *DkgState) SetIsValidator(isValidator bool) {
	state.Lock()
	defer state.Unlock()

	state.isValidator = isValidator
}

// GetPhase returns phase value
func (state *DkgState) GetPhase() EthDKGPhase {
	state.RLock()
	defer state.RUnlock()

	return state.phase
}

// SetPhase updates phase value
func (state *DkgState) SetPhase(phase EthDKGPhase) {
	state.Lock()
	defer state.Unlock()

	state.phase = phase
}

// GetPhaseLength returns phaseLength value
func (state *DkgState) GetPhaseLength() uint64 {
	state.RLock()
	defer state.RUnlock()

	return state.phaseLength
}

// SetPhaseLength updates phaseLength value
func (state *DkgState) SetPhaseLength(phaseLength uint64) {
	state.Lock()
	defer state.Unlock()

	state.phaseLength = phaseLength
}

// GetConfirmationLength returns confirmationLength value
func (state *DkgState) GetConfirmationLength() uint64 {
	state.RLock()
	defer state.RUnlock()

	return state.confirmationLength
}

// SetConfirmationLength updates confirmationLength value
func (state *DkgState) SetConfirmationLength(confirmationLength uint64) {
	state.Lock()
	defer state.Unlock()

	state.confirmationLength = confirmationLength
}

// GetPhaseStart returns phaseStart value
func (state *DkgState) GetPhaseStart() uint64 {
	state.RLock()
	defer state.RUnlock()

	return state.phaseStart
}

// SetPhaseStart updates phaseStart value
func (state *DkgState) SetPhaseStart(phaseStart uint64) {
	state.Lock()
	defer state.Unlock()

	state.phaseStart = phaseStart
}

// GetMPKSetAtBlock returns mpkSetAtBlock value
func (state *DkgState) GetMPKSetAtBlock() uint64 {
	state.RLock()
	defer state.RUnlock()

	return state.mpkSetAtBlock
}

// SetMPKSetAtBlock updates mpkSetAtBlock value
func (state *DkgState) SetMPKSetAtBlock(mpkSetAtBlock uint64) {
	state.Lock()
	defer state.Unlock()

	state.mpkSetAtBlock = mpkSetAtBlock
}

// GetCompletionAtBlock returns completionAtBlock value
func (state *DkgState) GetCompletionAtBlock() uint64 {
	state.RLock()
	defer state.RUnlock()

	return state.completionAtBlock
}

// SetCompletionAtBlock updates completionAtBlock value
func (state *DkgState) SetCompletionAtBlock(completionAtBlock uint64) {
	state.Lock()
	defer state.Unlock()

	state.completionAtBlock = completionAtBlock
}

// GetAccount returns account value
func (state *DkgState) GetAccount() accounts.Account {
	state.RLock()
	defer state.RUnlock()

	return state.account
}

// SetAccount updates account value
func (state *DkgState) SetAccount(account accounts.Account) {
	state.Lock()
	defer state.Unlock()

	state.account = account
}

// GetIndex returns index value
func (state *DkgState) GetIndex() int {
	state.RLock()
	defer state.RUnlock()

	return state.index
}

// SetIndex updates index value
func (state *DkgState) SetIndex(index int) {
	state.Lock()
	defer state.Unlock()

	state.index = index
}

// GetValidatorAddresses returns validatorAddresses value
func (state *DkgState) GetValidatorAddresses() []common.Address {
	state.RLock()
	defer state.RUnlock()

	validatorAddresses := make([]common.Address, len(state.validatorAddresses))
	for i := 0; i < len(state.validatorAddresses); i++ {
		validatorAddress := state.validatorAddresses[i].Bytes()
		validatorAddresses[i].SetBytes(validatorAddress)
	}

	return state.validatorAddresses
}

// SetValidatorAddresses updates validatorAddresses value
func (state *DkgState) SetValidatorAddresses(validatorAddresses []common.Address) {
	state.Lock()
	defer state.Unlock()

	state.validatorAddresses = make([]common.Address, len(validatorAddresses))
	for i := 0; i < len(validatorAddresses); i++ {
		validatorAddress := validatorAddresses[i].Bytes()
		state.validatorAddresses[i].SetBytes(validatorAddress)
	}

	state.validatorAddresses = validatorAddresses
}

// GetNumberOfValidators returns numberOfValidators value
func (state *DkgState) GetNumberOfValidators() int {
	state.RLock()
	defer state.RUnlock()

	return state.numberOfValidators
}

// SetNumberOfValidators updates numberOfValidators value
func (state *DkgState) SetNumberOfValidators(numberOfValidators int) {
	state.Lock()
	defer state.Unlock()

	state.numberOfValidators = numberOfValidators
}

// GetNonce returns nonce value
func (state *DkgState) GetNonce() uint64 {
	state.RLock()
	defer state.RUnlock()

	return state.nonce
}

// SetNonce updates nonce value
func (state *DkgState) SetNonce(nonce uint64) {
	state.Lock()
	defer state.Unlock()

	state.nonce = nonce
}

// GetValidatorThreshold returns validatorThreshold value
func (state *DkgState) GetValidatorThreshold() int {
	state.RLock()
	defer state.RUnlock()

	return state.validatorThreshold
}

// SetValidatorThreshold updates validatorThreshold value
func (state *DkgState) SetValidatorThreshold(validatorThreshold int) {
	state.Lock()
	defer state.Unlock()

	state.validatorThreshold = validatorThreshold
}

// GetTransportPrivateKey returns transportPrivateKey value
func (state *DkgState) GetTransportPrivateKey() *big.Int {
	state.RLock()
	defer state.RUnlock()

	return new(big.Int).Set(state.transportPrivateKey)
}

// SetTransportPrivateKey updates transportPrivateKey value
func (state *DkgState) SetTransportPrivateKey(transportPrivateKey *big.Int) {
	state.Lock()
	defer state.Unlock()

	state.transportPrivateKey = new(big.Int).Set(transportPrivateKey)
}

// GetTransportPublicKey returns transportPublicKey value
func (state *DkgState) GetTransportPublicKey() [2]*big.Int {
	state.RLock()
	defer state.RUnlock()

	transportPublicKey := [2]*big.Int{
		new(big.Int).Set(state.transportPublicKey[0]),
		new(big.Int).Set(state.transportPublicKey[1]),
	}
	return transportPublicKey
}

// SetTransportPublicKey updates transportPublicKey value
func (state *DkgState) SetTransportPublicKey(transportPublicKey [2]*big.Int) {
	state.Lock()
	defer state.Unlock()

	state.transportPublicKey = [2]*big.Int{
		new(big.Int).Set(transportPublicKey[0]),
		new(big.Int).Set(transportPublicKey[1]),
	}
}

// GetSecretValue returns secretValue value
func (state *DkgState) GetSecretValue() *big.Int {
	state.RLock()
	defer state.RUnlock()

	return new(big.Int).Set(state.secretValue)
}

// SetSecretValue updates secretValue value
func (state *DkgState) SetSecretValue(secretValue *big.Int) {
	state.Lock()
	defer state.Unlock()

	state.secretValue = new(big.Int).Set(secretValue)
}

// GetPrivateCoefficients returns privateCoefficients value
func (state *DkgState) GetPrivateCoefficients() []*big.Int {
	state.RLock()
	defer state.RUnlock()

	privateCoefficients := make([]*big.Int, len(state.privateCoefficients))
	for i := 0; i < len(state.privateCoefficients); i++ {
		privateCoefficients[i] = new(big.Int).Set(state.privateCoefficients[i])
	}

	return privateCoefficients
}

// SetPrivateCoefficients updates privateCoefficients value
func (state *DkgState) SetPrivateCoefficients(privateCoefficients []*big.Int) {
	state.Lock()
	defer state.Unlock()

	state.privateCoefficients = make([]*big.Int, len(privateCoefficients))
	for i := 0; i < len(privateCoefficients); i++ {
		state.privateCoefficients[i] = new(big.Int).Set(privateCoefficients[i])
	}
}

// GetMasterPublicKey returns masterPublicKey value
func (state *DkgState) GetMasterPublicKey() [4]*big.Int {
	state.RLock()
	defer state.RUnlock()

	masterPublicKey := [4]*big.Int{
		new(big.Int).Set(state.masterPublicKey[0]),
		new(big.Int).Set(state.masterPublicKey[1]),
		new(big.Int).Set(state.masterPublicKey[2]),
		new(big.Int).Set(state.masterPublicKey[3]),
	}
	return masterPublicKey
}

// SetMasterPublicKey updates masterPublicKey value
func (state *DkgState) SetMasterPublicKey(masterPublicKey [4]*big.Int) {
	state.Lock()
	defer state.Unlock()

	state.masterPublicKey = [4]*big.Int{
		new(big.Int).Set(masterPublicKey[0]),
		new(big.Int).Set(masterPublicKey[1]),
		new(big.Int).Set(masterPublicKey[2]),
		new(big.Int).Set(masterPublicKey[3]),
	}
}

// GetGroupPrivateKey returns groupPrivateKey value
func (state *DkgState) GetGroupPrivateKey() *big.Int {
	state.RLock()
	defer state.RUnlock()

	return new(big.Int).Set(state.groupPrivateKey)
}

// SetGroupPrivateKey updates groupPrivateKey value
func (state *DkgState) SetGroupPrivateKey(groupPrivateKey *big.Int) {
	state.Lock()
	defer state.Unlock()

	state.groupPrivateKey = new(big.Int).Set(groupPrivateKey)
}

// GetParticipants returns participants value
func (state *DkgState) GetParticipants() map[common.Address]*Participant {
	state.RLock()
	defer state.RUnlock()

	participants := make(map[common.Address]*Participant)
	for addr, participant := range state.participants {
		participants[addr] = participant.Clone()
	}

	return participants
}

// SetParticipants updates participants value
func (state *DkgState) SetParticipants(participants map[common.Address]*Participant) {
	state.Lock()
	defer state.Unlock()

	state.participants = make(map[common.Address]*Participant)
	for addr, participant := range participants {
		state.participants[addr] = participant.Clone()
	}
}

// GetBadShares returns badShares value
func (state *DkgState) GetBadShares() map[common.Address]*Participant {
	state.RLock()
	defer state.RUnlock()

	badShares := make(map[common.Address]*Participant)
	for addr, participant := range state.badShares {
		badShares[addr] = participant.Clone()
	}

	return badShares
}

// SetBadShares updates badShares value
func (state *DkgState) SetBadShares(badShares map[common.Address]*Participant) {
	state.Lock()
	defer state.Unlock()

	state.badShares = make(map[common.Address]*Participant)
	for addr, participant := range badShares {
		state.badShares[addr] = participant.Clone()
	}
}

// GetDishonestValidators returns dishonestValidators value
func (state *DkgState) GetDishonestValidators() ParticipantList {
	state.RLock()
	defer state.RUnlock()

	dishonestValidators := make(ParticipantList, state.dishonestValidators.Len())
	for i := 0; i < state.dishonestValidators.Len(); i++ {
		dishonestValidators[i] = state.dishonestValidators[i].Clone()
	}

	return dishonestValidators
}

// SetDishonestValidators updates dishonestValidators value
func (state *DkgState) SetDishonestValidators(dishonestValidators ParticipantList) {
	state.Lock()
	defer state.Unlock()

	state.dishonestValidators = make(ParticipantList, dishonestValidators.Len())
	for i := 0; i < state.dishonestValidators.Len(); i++ {
		state.dishonestValidators[i] = dishonestValidators[i].Clone()
	}
}

// GetHonestValidators returns honestValidators value
func (state *DkgState) GetHonestValidators() ParticipantList {
	state.RLock()
	defer state.RUnlock()

	honestValidators := make(ParticipantList, state.honestValidators.Len())
	for i := 0; i < state.honestValidators.Len(); i++ {
		honestValidators[i] = state.honestValidators[i].Clone()
	}

	return honestValidators
}

// SetHonestValidators updates honestValidators value
func (state *DkgState) SetHonestValidators(honestValidators ParticipantList) {
	state.Lock()
	defer state.Unlock()

	state.honestValidators = make(ParticipantList, honestValidators.Len())
	for i := 0; i < state.honestValidators.Len(); i++ {
		state.honestValidators[i] = honestValidators[i].Clone()
	}
}

// GetInverse returns inverse value
func (state *DkgState) GetInverse() []*big.Int {
	state.RLock()
	defer state.RUnlock()

	inverse := make([]*big.Int, len(state.inverse))
	for i := 0; i < len(state.inverse); i++ {
		inverse[i] = new(big.Int).Set(state.inverse[i])
	}

	return inverse
}

// SetInverse updates inverse value
func (state *DkgState) SetInverse(inverse []*big.Int) {
	state.Lock()
	defer state.Unlock()

	state.inverse = make([]*big.Int, len(inverse))
	for i := 0; i < len(inverse); i++ {
		state.inverse[i] = new(big.Int).Set(inverse[i])
	}
}

// GetSortedParticipants returns the participant list sorted by Index field
func (state *DkgState) GetSortedParticipants() ParticipantList {
	state.RLock()
	defer state.RUnlock()

	var list = make(ParticipantList, len(state.participants))

	for _, p := range state.participants {
		list[p.Index-1] = p.Clone()
	}

	return list
}

// OnRegistrationOpened processes data from RegistrationOpened event
func (state *DkgState) OnRegistrationOpened(startBlock, phaseLength, confirmationLength, nonce uint64) {
	state.Lock()
	defer state.Unlock()

	state.phase = RegistrationOpen
	state.phaseStart = startBlock
	state.phaseLength = phaseLength
	state.confirmationLength = confirmationLength
	state.nonce = nonce
}

// OnAddressRegistered processes data from AddressRegistered event
func (state *DkgState) OnAddressRegistered(account common.Address, index int, nonce uint64, publicKey [2]*big.Int) {
	state.Lock()
	defer state.Unlock()

	state.participants[account] = &Participant{
		Address: account,
		Index:   index,
		PublicKey: [2]*big.Int{
			new(big.Int).Set(publicKey[0]),
			new(big.Int).Set(publicKey[1]),
		},
		Phase: uint8(RegistrationOpen),
		Nonce: nonce,
	}

	// update state.Index with my index, if this event was mine
	if account.String() == state.account.Address.String() {
		state.index = index
	}
}

// OnRegistrationComplete processes data from RegistrationComplete event
func (state *DkgState) OnRegistrationComplete(shareDistributionStartBlockNumber uint64) {
	state.Lock()
	defer state.Unlock()

	state.phase = ShareDistribution
	state.phaseStart = shareDistributionStartBlockNumber + state.confirmationLength
}

// OnSharesDistributed processes data from SharesDistributed event
func (state *DkgState) OnSharesDistributed(logger *logrus.Entry, account common.Address, encryptedShares []*big.Int, commitments [][2]*big.Int) error {
	// compute distributed shares hash
	distributedSharesHash, _, _, err := dkg.ComputeDistributedSharesHash(encryptedShares, commitments)
	if err != nil {
		return dkg.LogReturnErrorf(logger, "ProcessShareDistribution: error calculating distributed shares hash: %v", err)
	}

	state.Lock()
	defer state.Unlock()

	state.participants[account].Phase = uint8(ShareDistribution)
	state.participants[account].DistributedSharesHash = distributedSharesHash
	state.participants[account].Commitments = commitments
	state.participants[account].EncryptedShares = encryptedShares

	return nil
}

// OnShareDistributionComplete processes data from ShareDistributionComplete event
func (state *DkgState) OnShareDistributionComplete(disputeShareDistributionStartBlock uint64) {
	state.Lock()
	defer state.Unlock()

	state.phase = DisputeShareDistribution

	// schedule DisputeShareDistributionTask
	dispShareStartBlock := disputeShareDistributionStartBlock + state.confirmationLength
	state.phaseStart = dispShareStartBlock
}

// OnKeyShareSubmissionComplete processes data from KeyShareSubmissionComplete event
func (state *DkgState) OnKeyShareSubmissionComplete(mpkSubmissionStartBlock uint64) {
	state.Lock()
	defer state.Unlock()

	state.phase = MPKSubmission
	state.phaseStart = mpkSubmissionStartBlock + state.confirmationLength
}

// OnMPKSet processes data from MPKSet event
func (state *DkgState) OnMPKSet(gpkjSubmissionStartBlock uint64) {
	state.Lock()
	defer state.Unlock()

	state.phase = GPKJSubmission
	state.phaseStart = gpkjSubmissionStartBlock
	state.mpkSetAtBlock = gpkjSubmissionStartBlock
}

// OnGPKJSubmissionComplete processes data from GPKJSubmissionComplete event
func (state *DkgState) OnGPKJSubmissionComplete(disputeGPKjStartBlock uint64) {
	state.Lock()
	defer state.Unlock()

	state.phase = DisputeGPKJSubmission
	state.phaseStart = disputeGPKjStartBlock + state.confirmationLength
}

// OnKeyShareSubmitted processes data from KeyShareSubmitted event
func (state *DkgState) OnKeyShareSubmitted(account common.Address, keyShareG1 [2]*big.Int, keyShareG1CorrectnessProof [2]*big.Int, keyShareG2 [4]*big.Int) {
	state.Lock()
	defer state.Unlock()

	state.phase = KeyShareSubmission
	state.participants[account].Phase = uint8(KeyShareSubmission)
	state.participants[account].KeyShareG1s = keyShareG1
	state.participants[account].KeyShareG1CorrectnessProofs = keyShareG1CorrectnessProof
	state.participants[account].KeyShareG2s = keyShareG2
}

// OnGPKjSubmitted processes data from GPKjSubmitted event
func (state *DkgState) OnGPKjSubmitted(account common.Address, gpkj [4]*big.Int) {
	state.Lock()
	defer state.Unlock()

	state.participants[account].GPKj = gpkj
	state.participants[account].Phase = uint8(GPKJSubmission)
}

// OnCompletion processes data from ValidatorSetCompleted event
func (state *DkgState) OnCompletion() {
	state.Lock()
	defer state.Unlock()

	state.phase = Completion
}

// NewDkgState makes a new DkgState object
func NewDkgState(account accounts.Account) *DkgState {
	return &DkgState{
		account:      account,
		badShares:    make(map[common.Address]*Participant),
		participants: make(map[common.Address]*Participant),
	}
}

// Participant contains what we know about other participants, i.e. public information
type Participant struct {
	// Address is the Ethereum address corresponding to the Ethereum Public Key
	// for the Participant.
	Address common.Address
	// Index is the Base-1 index of the participant.
	// This is used during the Share Distribution phase to perform
	// verifyiable secret sharing.
	// REPEAT: THIS IS BASE-1
	Index int
	// PublicKey is the TransportPublicKey of Participant.
	PublicKey [2]*big.Int
	Nonce     uint64
	Phase     uint8

	// Share Distribution Phase
	//////////////////////////////////////////////////
	// Commitments stores the Public Coefficients
	// corresponding to public polynomial
	// in Shamir Secret Sharing protocol.
	// The first coefficient (constant term) is the public commitment
	// corresponding to the secret share (SecretValue).
	Commitments [][2]*big.Int
	// EncryptedShares are the encrypted secret shares
	// in the Shamir Secret Sharing protocol.
	EncryptedShares       []*big.Int
	DistributedSharesHash [32]byte

	CommitmentsFirstCoefficient [2]*big.Int

	// Key Share Submission Phase
	//////////////////////////////////////////////////
	// KeyShareG1s stores the key shares of G1 element
	// for each participant
	KeyShareG1s [2]*big.Int

	// KeyShareG1CorrectnessProofs stores the proofs of each
	// G1 element for each participant.
	KeyShareG1CorrectnessProofs [2]*big.Int

	// KeyShareG2s stores the key shares of G2 element
	// for each participant.
	// Adding all the G2 shares together produces the
	// master public key (MasterPublicKey).
	KeyShareG2s [4]*big.Int

	// GPKj is the local Validator's portion of the master public key.
	// This is also denoted GroupPublicKey.
	GPKj [4]*big.Int
}

// ParticipantList is a required type alias since the Sort interface is awful
type ParticipantList []*Participant

// Simplify logging
func (p *Participant) String() string {
	out, err := json.Marshal(p)
	if err != nil {
		return err.Error()
	}

	return string(out)
}

// Copy makes returns a copy of Participant
func (p *Participant) Copy() *Participant {
	c := &Participant{}
	c.Index = p.Index
	c.PublicKey = [2]*big.Int{
		new(big.Int).Set(p.PublicKey[0]),
		new(big.Int).Set(p.PublicKey[1]),
	}
	addrBytes := p.Address.Bytes()
	c.Address.SetBytes(addrBytes)
	return c
}

// Clone makes returns an exact clone of Participant
func (p *Participant) Clone() *Participant {
	c := &Participant{}
	addrBytes := p.Address.Bytes()
	c.Address.SetBytes(addrBytes)
	c.Index = p.Index
	c.PublicKey = [2]*big.Int{
		new(big.Int).Set(p.PublicKey[0]),
		new(big.Int).Set(p.PublicKey[1]),
	}
	c.Nonce = p.Nonce
	c.Phase = p.Phase

	commitments := make([][2]*big.Int, len(p.Commitments))
	for i := 0; i < len(p.Commitments); i++ {
		commitments[i] = [2]*big.Int{
			new(big.Int).Set(p.Commitments[i][0]),
			new(big.Int).Set(p.Commitments[i][1]),
		}
	}
	c.Commitments = commitments

	encryptedShares := make([]*big.Int, len(p.EncryptedShares))
	for i := 0; i < len(p.EncryptedShares); i++ {
		encryptedShares[i] = new(big.Int).Set(p.EncryptedShares[i])
	}
	c.EncryptedShares = encryptedShares

	c.DistributedSharesHash = p.DistributedSharesHash
	c.CommitmentsFirstCoefficient = [2]*big.Int{
		new(big.Int).Set(p.CommitmentsFirstCoefficient[0]),
		new(big.Int).Set(p.CommitmentsFirstCoefficient[1]),
	}
	c.KeyShareG1s = [2]*big.Int{
		new(big.Int).Set(p.KeyShareG1s[0]),
		new(big.Int).Set(p.KeyShareG1s[1]),
	}
	c.KeyShareG1CorrectnessProofs = [2]*big.Int{
		new(big.Int).Set(p.KeyShareG1CorrectnessProofs[0]),
		new(big.Int).Set(p.KeyShareG1CorrectnessProofs[1]),
	}
	c.KeyShareG2s = [4]*big.Int{
		new(big.Int).Set(p.KeyShareG2s[0]),
		new(big.Int).Set(p.KeyShareG2s[1]),
		new(big.Int).Set(p.KeyShareG2s[2]),
		new(big.Int).Set(p.KeyShareG2s[3]),
	}
	c.GPKj = [4]*big.Int{
		new(big.Int).Set(p.GPKj[0]),
		new(big.Int).Set(p.GPKj[1]),
		new(big.Int).Set(p.GPKj[2]),
		new(big.Int).Set(p.GPKj[3]),
	}

	return c
}

// ExtractIndices returns the list of indices of ParticipantList
func (pl ParticipantList) ExtractIndices() []int {
	indices := []int{}
	for k := 0; k < len(pl); k++ {
		indices = append(indices, pl[k].Index)
	}
	return indices
}

// Len returns the len of the collection
func (pl ParticipantList) Len() int {
	return len(pl)
}

// Less decides if element i is 'Less' than element j -- less ~= before
func (pl ParticipantList) Less(i, j int) bool {
	return pl[i].Index < pl[j].Index
}

// Swap swaps elements i and j within the collection
func (pl ParticipantList) Swap(i, j int) {
	pl[i], pl[j] = pl[j], pl[i]
}
