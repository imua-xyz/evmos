// Copyright Tharsis Labs Ltd.(Evmos)
// SPDX-License-Identifier:ENCL-1.0(https://github.com/evmos/evmos/blob/main/LICENSE)
package common

import (
	"fmt"
	"time"

	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	authzkeeper "github.com/cosmos/cosmos-sdk/x/authz/keeper"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/evmos/evmos/v16/x/evm/statedb"
)

// Precompile is a common struct for all precompiles that holds the common data each
// precompile needs to run which includes the ABI, Gas config, approval expiration and the authz keeper.
type Precompile struct {
	abi.ABI
	AuthzKeeper          authzkeeper.Keeper
	ApprovalExpiration   time.Duration
	KvGasConfig          storetypes.GasConfig
	TransientKVGasConfig storetypes.GasConfig
	// Addr is the address of the precompile
	// we use Addr not Address since Address is the function name
	Addr common.Address
}

// RequiredGas calculates the base minimum required gas for a transaction or a query.
// It uses the method ID to determine if the input is a transaction or a query and
// uses the Cosmos SDK gas config flat cost and the flat per byte cost * len(argBz) to calculate the gas.
func (p Precompile) RequiredGas(input []byte, isTransaction bool) uint64 {
	if len(input) < 4 {
		// Avoid panic when input is less than 4 bytes
		return 0
	}

	argsBz := input[4:]

	if isTransaction {
		return p.KvGasConfig.WriteCostFlat + (p.KvGasConfig.WriteCostPerByte * uint64(len(argsBz)))
	}

	return p.KvGasConfig.ReadCostFlat + (p.KvGasConfig.ReadCostPerByte * uint64(len(argsBz)))
}

// RunSetup runs the initial setup required to run a transaction or a query.
// It returns the sdk Context, EVM stateDB, ABI method, initial gas and calling arguments.
func (p Precompile) RunSetup(
	evm *vm.EVM,
	contract *vm.Contract,
	readOnly bool,
	isTransaction func(name string) bool,
) (ctx sdk.Context, stateDB *statedb.StateDB, method *abi.Method, gasConfig sdk.Gas, args []interface{}, err error) {
	stateDB, ok := evm.StateDB.(*statedb.StateDB)
	if !ok {
		return sdk.Context{}, nil, nil, sdk.Gas(0), nil, fmt.Errorf(ErrNotRunInEvm)
	}
	// operate on the cached context. the original
	// context is never touched by precompile calls.
	ctx, err = stateDB.GetCacheContext()
	if err != nil {
		return sdk.Context{}, nil, nil, sdk.Gas(0), nil, err
	}

	// take a snapshot of the current state before any changes.
	multiStore := stateDB.MultiStoreSnapshot()
	events := ctx.EventManager().Events()

	// NOTE: This is a special case where the calling transaction does not specify a function name.
	// In this case we default to a `fallback` or `receive` function on the contract.

	// Simplify the calldata checks
	isEmptyCallData := len(contract.Input) == 0
	isShortCallData := len(contract.Input) > 0 && len(contract.Input) < 4
	isStandardCallData := len(contract.Input) >= 4

	switch {
	// Case 1: Calldata is empty
	case isEmptyCallData:
		method, err = p.emptyCallData(contract)

	// Case 2: calldata is non-empty but less than 4 bytes needed for a method
	case isShortCallData:
		method, err = p.methodIDCallData()

	// Case 3: calldata is non-empty and contains the minimum 4 bytes needed for a method
	case isStandardCallData:
		method, err = p.standardCallData(contract)
	}

	if err != nil {
		// if the method is not found, it will exit here.
		// hence, isTransaction("unknown") will never be called, and
		// can safely panic.
		return sdk.Context{}, nil, nil, sdk.Gas(0), nil, err
	}

	if isTransaction(method.Name) {
		if readOnly {
			// return error if trying to write to state during a read-only call
			return sdk.Context{}, nil, nil, sdk.Gas(0), nil, vm.ErrWriteProtection
		}
		// add a snapshot of the current state before executing the precompile
		// so that any errors during said execution are reverted correctly
		if err := stateDB.AddPrecompileFn(p.Address(), multiStore, events); err != nil {
			// native balance changes should be added in Run by the precompile.
			return sdk.Context{}, nil, nil, sdk.Gas(0), nil, err
		}
	}

	// if the method type is `function` continue looking for arguments
	if method.Type == abi.Function {
		argsBz := contract.Input[4:]
		args, err = method.Inputs.Unpack(argsBz)
		if err != nil {
			return sdk.Context{}, nil, nil, sdk.Gas(0), nil, err
		}
	}

	initialGas := ctx.GasMeter().GasConsumed()

	// if we are here, error is nil.
	defer HandleGasError(ctx, contract, initialGas, &err)()

	// set the default SDK gas configuration to track gas usage
	// we are changing the gas meter type, so it panics gracefully when out of gas
	ctx = ctx.WithGasMeter(sdk.NewGasMeter(contract.Gas)).
		WithKVGasConfig(p.KvGasConfig).
		WithTransientKVGasConfig(p.TransientKVGasConfig)
	// we need to consume the gas that was already used by the EVM
	ctx.GasMeter().ConsumeGas(initialGas, "creating a new gas meter")

	// return the error (set by HandleGasError) or nil
	if err != nil {
		return sdk.Context{}, nil, nil, sdk.Gas(0), nil, err
	}

	// dump every in-memory stateDB change to the in-memory cached context.
	// note that no disk commitment happens here.
	// previously, this was done at the top of this function and not here at
	// the bottom. that caused issues in case something else errored out
	// after the `CommitWithCacheCtx` call.
	// for example, if the precompile was called with an unknown method ID,
	// and stateDB.CommitWithCacheCtx() was called first, the cached context
	// would store an incorrect state without a corresponding journal entry.
	// in other words, this below function dumps the changes into `writeCache`,
	// which would override the disk-commitment with incorrect values.
	if err := stateDB.CommitWithCacheCtx(); err != nil {
		return sdk.Context{}, nil, nil, sdk.Gas(0), nil, err
	}

	return ctx, stateDB, method, sdk.Gas(initialGas), args, nil
}

// HandleGasError handles the out of gas panic by resetting the gas meter and returning an error.
// This is used in order to avoid panics and to allow for the EVM to continue cleanup if the tx or query run out of gas.
func HandleGasError(ctx sdk.Context, contract *vm.Contract, initialGas sdk.Gas, err *error) func() {
	return func() {
		if r := recover(); r != nil {
			switch r.(type) {
			case sdk.ErrorOutOfGas:
				// update contract gas
				usedGas := ctx.GasMeter().GasConsumed() - initialGas
				_ = contract.UseGas(usedGas)

				*err = vm.ErrOutOfGas
				// FIXME: add InfiniteGasMeter with previous Gas limit.
				ctx = ctx.WithKVGasConfig(storetypes.GasConfig{}).
					WithTransientKVGasConfig(storetypes.GasConfig{})
			default:
				panic(r)
			}
		}
	}
}

// emptyCallData is a helper function that returns the method to be called when the calldata is empty.
func (p Precompile) emptyCallData(contract *vm.Contract) (method *abi.Method, err error) {
	switch {
	// Case 1.1: Send call or transfer tx - 'receive' is called if present and value is transferred
	case contract.Value().Sign() > 0 && p.HasReceive():
		return &p.Receive, nil
	// Case 1.2: Either 'receive' is not present, or no value is transferred - call 'fallback' if present
	case p.HasFallback():
		return &p.Fallback, nil
	// Case 1.3: Neither 'receive' nor 'fallback' are present - return error
	default:
		return nil, vm.ErrExecutionReverted
	}
}

// methodIDCallData is a helper function that returns the method to be called when the calldata is less than 4 bytes.
func (p Precompile) methodIDCallData() (method *abi.Method, err error) {
	// Case 2.2: calldata contains less than 4 bytes needed for a method and 'fallback' is not present - return error
	if !p.HasFallback() {
		return nil, vm.ErrExecutionReverted
	}
	// Case 2.1: calldata contains less than 4 bytes needed for a method - 'fallback' is called if present
	return &p.Fallback, nil
}

// standardCallData is a helper function that returns the method to be called when the calldata is 4 bytes or more.
func (p Precompile) standardCallData(contract *vm.Contract) (method *abi.Method, err error) {
	methodID := contract.Input[:4]
	// NOTE: this function iterates over the method map and returns
	// the method with the given ID
	method, err = p.MethodById(methodID)

	// Case 3.1 calldata contains a non-existing method ID, and `fallback` is not present - return error
	if err != nil && !p.HasFallback() {
		return nil, err
	}

	// Case 3.2: calldata contains a non-existing method ID - 'fallback' is called if present
	if err != nil && p.HasFallback() {
		return &p.Fallback, nil
	}

	return method, nil
}

func (p Precompile) Address() common.Address {
	return p.Addr
}

func (p *Precompile) SetAddress(addr common.Address) {
	p.Addr = addr
}
