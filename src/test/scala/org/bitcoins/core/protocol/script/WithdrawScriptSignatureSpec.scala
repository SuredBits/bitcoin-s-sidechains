package org.bitcoins.core.protocol.script

import org.bitcoins.core.crypto.DoubleSha256Digest
import org.bitcoins.core.gen.{MerkleGenerator, ScriptGenerators, TransactionGenerators}
import org.bitcoins.core.number.UInt32
import org.bitcoins.core.protocol.blockchain.{Block, MerkleBlock}
import org.bitcoins.core.protocol.transaction.Transaction
import org.bitcoins.core.util.BitcoinSLogger
import org.scalacheck.{Gen, Prop, Properties}

/**
  * Created by chris on 3/13/17.
  */
class WithdrawScriptSignatureSpec extends Properties("WithdrawScriptSignatureSpec") with BitcoinSLogger {

  property("serialization symmetry") = {
    Prop.forAll(ScriptGenerators.withdrawScriptSignature) { scriptSig =>
      WithdrawScriptSignature(scriptSig.hex) == scriptSig &&
        WithdrawScriptSignature.fromAsm(scriptSig.asm) == scriptSig
    }
  }

  property("methods to access individual fields must work") =
    Prop.forAllNoShrink(ScriptGenerators.contract, MerkleGenerator.merkleBlockWithInsertedTxIds,
      TransactionGenerators.transaction) { case (contract: Contract,
    merkleBlockTuple: (MerkleBlock,Block,Seq[DoubleSha256Digest]),
    lockingTx: Transaction) =>
      val (merkleBlock,_,_) = merkleBlockTuple
      val outputIndex = UInt32(Gen.choose(0,lockingTx.outputs.size).sample.get)
      val scriptSig = WithdrawScriptSignature(contract,merkleBlock,lockingTx,outputIndex)
      scriptSig.contract == contract &&
      scriptSig.merkleBlock == merkleBlock &&
      scriptSig.lockingTransaction == lockingTx &&
      scriptSig.lockTxOutputIndex == outputIndex
    }

}
