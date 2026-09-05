// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
// Run from the pinned utreexod checkout; see doc/transaction-proof-codec.md.
// This uses the real Go accumulator and wire encoder as an independent oracle.
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"math/bits"
	"os"
	"strings"

	"github.com/utreexo/utreexo"
	"github.com/utreexo/utreexod/chaincfg/chainhash"
	"github.com/utreexo/utreexod/wire"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func encoded(message wire.Message) []byte {
	var buf bytes.Buffer
	check(message.BtcEncode(&buf, wire.ProtocolVersion, wire.WitnessEncoding))
	return buf.Bytes()
}

func nativePosition(pos uint64, rows uint8) uint64 {
	row := uint8(bits.LeadingZeros64(^pos))
	if row == 0 {
		return pos
	}
	start := ^uint64(0) ^ (^uint64(0) >> row)
	mask := (uint64(2) << rows) - 1
	return pos - start + (mask ^ (mask >> row))
}

func ints(values []uint64) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprintf("%dULL", value)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func hashes(values []utreexo.Hash) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = fmt.Sprintf("\"%x\"", value[:])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func scenario(out *bytes.Buffer, name string, witness bool, leafCount int, selected []int, deleteFirst bool) {
	tx := wire.NewMsgTx(2)
	tx.LockTime = 42
	leaves := make([]wire.LeafData, len(selected))
	adds := make([]utreexo.Leaf, leafCount)
	for i := range adds {
		adds[i] = utreexo.Leaf{Hash: utreexo.Hash{byte(i + 1), 0xab}, Remember: true}
	}
	var targetHashes []utreexo.Hash
	for i, selectedLeaf := range selected {
		outpoint := wire.OutPoint{Hash: chainhash.Hash{byte(i + 1), 0xcd}, Index: uint32(i * 257)}
		if i == len(selected)-1 {
			outpoint.Index = 0x7fffffff // highest losslessly flaggable vout
		}
		var stack wire.TxWitness
		if witness && i%2 == 0 {
			stack = wire.TxWitness{[]byte{0x30, byte(i)}, {}, bytes.Repeat([]byte{0x02}, 253)}
		}
		tx.AddTxIn(wire.NewTxIn(&outpoint, []byte{0x02, 0xaa, byte(i)}, stack))
		tx.TxIn[i].Sequence = uint32(0xfffffffd - i)
		ld := wire.LeafData{OutPoint: outpoint, BlockHash: chainhash.Hash{byte(i + 1), 0xef},
			Height: int32(100 + i), IsCoinBase: i%2 == 0, Amount: int64(1000 + i),
			ReconstructablePkType: wire.PkType(len(targetHashes) % 5)}
		if selectedLeaf < 0 {
			ld.SetUnconfirmed()
		} else {
			if ld.ReconstructablePkType == wire.OtherTy {
				ld.PkScript = bytes.Repeat([]byte{0x51}, 253)
			}
			leafHash := ld.LeafHash()
			adds[selectedLeaf].Hash = leafHash
			targetHashes = append(targetHashes, leafHash)
		}
		leaves[i] = ld
	}
	tx.AddTxOut(wire.NewTxOut(123456, []byte{0x51}))
	tx.AddTxOut(wire.NewTxOut(0, []byte{0x6a, 0x02, 0xaa, 0xbb}))
	acc := utreexo.NewAccumulator()
	check(acc.Modify(adds, nil, utreexo.Proof{}))
	if deleteFirst {
		dels := []utreexo.Hash{adds[0].Hash}
		proof, err := acc.Prove(dels)
		check(err)
		check(acc.Modify(nil, dels, proof))
	}
	proof, err := acc.Prove(targetHashes)
	check(err)
	check(acc.Verify(targetHashes, proof, false))
	consumer := utreexo.NewMapPollardFromRoots(acc.GetRoots(), acc.NumLeaves)
	// The root-only constructor leaves TotalRows unset; a live/deserialized
	// compact accumulator has the current tree height.
	consumer.TotalRows = utreexo.TreeRows(acc.NumLeaves)
	positions := consumer.GetMissingPositions(proof.Targets)
	if len(positions) != len(proof.Proof) {
		panic("consumer full request does not match generated proof")
	}
	inv := wire.NewMsgInv()
	txid := tx.TxHash()
	check(inv.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &txid)))
	for _, packed := range chainhash.Uint64sToPackedHashes(proof.Targets) {
		check(inv.AddInvVect(wire.NewInvVect(wire.InvTypeUtreexoProofHash, &packed)))
	}
	native := make([]uint64, len(proof.Targets))
	for i, target := range proof.Targets {
		native[i] = nativePosition(target, utreexo.TreeRows(acc.NumLeaves))
	}
	for _, mode := range []string{"full", "partial", "zero", "witness_request"} {
		var requested []uint64
		var requestedHashes []utreexo.Hash
		switch mode {
		case "full", "witness_request":
			requested, requestedHashes = positions, proof.Proof
		case "partial":
			// Deliberately reverse the request order to catch hash/target sorting bugs.
			for i := len(positions) - 1; i >= 0; i -= 2 {
				requested = append(requested, positions[i])
				requestedHashes = append(requestedHashes, proof.Proof[i])
			}
		}
		requestType := wire.InvTypeUtreexoTx
		if mode == "witness_request" {
			requestType = wire.InvTypeWitnessUtreexoTx
		}
		request := wire.NewMsgGetData()
		check(request.AddInvVect(wire.NewInvVect(requestType, &txid)))
		for _, packed := range chainhash.Uint64sToPackedHashes(requested) {
			check(request.AddInvVect(wire.NewInvVect(wire.InvTypeUtreexoProofHash, &packed)))
		}
		message := &wire.MsgUtreexoTx{MsgTx: *tx.Copy(), LeafDatas: leaves,
			AccProof: utreexo.Proof{Targets: proof.Targets, Proof: requestedHashes}}
		payload := encoded(message)
		var decoded wire.MsgUtreexoTx
		reader := bytes.NewReader(payload)
		check(decoded.BtcDecode(reader, wire.ProtocolVersion, wire.WitnessEncoding))
		if reader.Len() != 0 || decoded.TxHash() != txid || decoded.WitnessHash() != tx.WitnessHash() {
			panic("Go wire round trip changed transaction identity")
		}
		fmt.Fprintf(out, "    {\n        .name = %q,\n", name+"_"+mode)
		for _, field := range []struct{ name, value string }{
			{"raw", hex.EncodeToString(encoded(tx))}, {"txid", txid.String()},
			{"wtxid", tx.WitnessHash().String()}, {"announcement", hex.EncodeToString(encoded(inv))},
			{"request", hex.EncodeToString(encoded(request))}, {"response", hex.EncodeToString(payload)},
		} {
			fmt.Fprintf(out, "        .%s = %q,\n", field.name, field.value)
		}
		fmt.Fprintf(out, "        .num_leaves = %d,\n        .native_targets = %s,\n", acc.NumLeaves, ints(native))
		fmt.Fprintf(out, "        .wire_targets = %s,\n        .proof_positions = %s,\n", ints(proof.Targets), ints(positions))
		fmt.Fprintf(out, "        .requested_positions = %s,\n        .inventory_type = %d,\n", ints(requested), requestType)
		fmt.Fprintf(out, "        .proof_hashes = %s,\n        .target_hashes = %s,\n        .roots = %s,\n", hashes(proof.Proof), hashes(targetHashes), hashes(acc.GetRoots()))
		fmt.Fprintln(out, "        .leaves = {")
		for _, ld := range leaves {
			if ld.IsUnconfirmed() {
				fmt.Fprintln(out, "            {false, 0, 0, 0, \"\"},")
			} else {
				header := uint32(ld.Height) << 1
				if ld.IsCoinBase {
					header |= 1
				}
				fmt.Fprintf(out, "            {true, %d, %d, %d, \"%x\"},\n", header, ld.Amount, ld.ReconstructablePkType, ld.PkScript)
			}
		}
		fmt.Fprintln(out, "        },\n    },")
	}
}

func main() {
	checkPath := flag.String("check", "", "compare generated bytes with this fixture file")
	flag.Parse()
	var out bytes.Buffer
	fmt.Fprintln(&out, "// Generated by test/integration/utreexod_tx_vectors.go. Do not edit.")
	fmt.Fprintln(&out, "// utreexod v0.6.0 fe71f3d9282ef0812f7f6087f0c0df9ce0fda508; utreexo v0.18.0.")
	fmt.Fprintln(&out, "const std::vector<TxVector> TX_VECTORS{")
	scenario(&out, "legacy_mixed", false, 8, []int{5, -1, 0}, false)
	scenario(&out, "witness_mixed", true, 16, []int{10, -1, 3, 14, 0, 7}, false)
	scenario(&out, "promoted", true, 8, []int{1, -1, 6}, true)
	scenario(&out, "unconfirmed", true, 0, []int{-1, -1}, false)
	scenario(&out, "root", false, 1, []int{0}, false)
	fmt.Fprintln(&out, "};")
	if *checkPath != "" {
		expected, err := os.ReadFile(*checkPath)
		check(err)
		if !bytes.Equal(expected, out.Bytes()) {
			panic("checked-in transaction codec fixtures differ from pinned Go encoding")
		}
		fmt.Println("20 transaction proof fixtures match pinned utreexod encoding")
		return
	}
	_, err := os.Stdout.Write(out.Bytes())
	check(err)
}
