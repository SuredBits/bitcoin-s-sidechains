package org.bitcoins.core.crypto

import org.bitcoins.core.gen.TransactionGenerators
import org.bitcoins.core.number.Int64
import org.bitcoins.core.protocol.script.{CLTVScriptPubKey, P2SHScriptPubKey}
import org.bitcoins.core.script.interpreter.ScriptInterpreter
import org.bitcoins.core.script.result.{ScriptErrorUnsatisfiedLocktime, ScriptErrorPushSize, ScriptOk}
import org.bitcoins.core.script.{PreExecutionScriptProgram, ScriptProgram}
import org.bitcoins.core.util.BitcoinSLogger
import org.scalacheck.{Prop, Properties}

/**
  * Created by chris on 7/25/16.
  */
class TransactionSignatureCreatorSpec extends Properties("TransactionSignatureCreatorSpec") with BitcoinSLogger {

  property("Must generate a valid signature for a p2pk transaction") =
    Prop.forAll(TransactionGenerators.signedP2PKTransaction) {
      case (txSignatureComponent: TransactionSignatureComponent, _) =>
        //run it through the interpreter
        val program: PreExecutionScriptProgram = ScriptProgram(txSignatureComponent)
        val result = ScriptInterpreter.run(program)
        result == ScriptOk
    }

  property("generate a valid signature for a p2pkh transaction") =
    Prop.forAll(TransactionGenerators.signedP2PKHTransaction) {
      case (txSignatureComponent: TransactionSignatureComponent, _) =>
        //run it through the interpreter
        val program = ScriptProgram(txSignatureComponent)
        val result = ScriptInterpreter.run(program)
        result == ScriptOk
    }
  property("generate valid signatures for a multisignature transaction") =
    Prop.forAllNoShrink(TransactionGenerators.signedMultiSigTransaction) {
      case (txSignatureComponent: TransactionSignatureComponent, _)  =>
        //run it through the interpreter
        val program = ScriptProgram(txSignatureComponent)
        val result = ScriptInterpreter.run(program)
        logger.info("result: " + result)
        result == ScriptOk
  }

  property("generate a valid signature for a p2sh transaction") =
    Prop.forAll(TransactionGenerators.signedP2SHTransaction) {
      case (txSignatureComponent: TransactionSignatureComponent, _) =>
        //run it through the interpreter
        val program = ScriptProgram(txSignatureComponent)
        val result = ScriptInterpreter.run(program)
        //can be ScriptErrorPushSize if the redeemScript is larger than 520 bytes
        Seq(ScriptOk, ScriptErrorPushSize).contains(result)
    }

  property("generate a valid signature for a valid and spendable cltv transaction") =
    Prop.forAllNoShrink(TransactionGenerators.spendableCLTVTransaction :| "cltv_spendable") {
      case (txSignatureComponent: TransactionSignatureComponent, _, scriptNumber) =>
        //run it through the interpreter
        require(txSignatureComponent.transaction.lockTime.underlying >= scriptNumber.underlying, "TxLocktime must be satisfied so it should be greater than or equal to  " +
          "the cltv value. Got TxLockTime : " + txSignatureComponent.transaction.lockTime.underlying + " , and cltv Value: " +
          scriptNumber.underlying)
        val program = ScriptProgram(txSignatureComponent)
        val result = ScriptInterpreter.run(program)
        result == ScriptOk
    }

  property("fail to verify a transaction with a locktime that has not yet been met") =
    Prop.forAllNoShrink(TransactionGenerators.unspendableCLTVTransaction :| "cltv_unspendable") {
      case (txSignatureComponent: TransactionSignatureComponent, _, scriptNumber) =>
        //run it through the interpreter
        require(txSignatureComponent.transaction.lockTime.underlying < scriptNumber.underlying, "TxLocktime must not be satisfied so it should be less than " +
          "the cltv value. Got TxLockTime : " + txSignatureComponent.transaction.lockTime.underlying + " , and cltv Value: " +
          scriptNumber.underlying)
        val program = ScriptProgram(txSignatureComponent)
        val result = ScriptInterpreter.run(program)
        Seq(ScriptErrorUnsatisfiedLocktime, ScriptErrorPushSize).contains(result)
    }

  property("generate a valid signature for a valid and spendable csv transaction") =
    Prop.forAllNoShrink(TransactionGenerators.spendableCSVTransaction :| "spendable csv") {
      case (txSignatureComponent: TransactionSignatureComponent, keys, scriptNumber, sequence) =>
        //run it through the interpreter
        val program = ScriptProgram(txSignatureComponent)
        val result = ScriptInterpreter.run(program)
        Seq(ScriptOk, ScriptErrorPushSize).contains(result)
    }

  property("fail to verify a transaction with a relative locktime that has not been satisfied yet") =
    Prop.forAllNoShrink(TransactionGenerators.unspendableCSVTransaction :| "unspendable csv") {
      case (txSignatureComponent: TransactionSignatureComponent, keys, scriptNumber, sequence) =>
        //run it through the interpreter
        val program = ScriptProgram(txSignatureComponent)
        val result = ScriptInterpreter.run(program)
        Seq(ScriptErrorUnsatisfiedLocktime, ScriptErrorPushSize).contains(result)

    }

  property("generate a valid signature for a p2wpkh witness transaction") =
    Prop.forAllNoShrink(TransactionGenerators.signedP2WPKHTransaction) { case (wtxSigComponent, privKeys) =>
        val program = ScriptProgram(wtxSigComponent)
        val result = ScriptInterpreter.run(program)
        result == ScriptOk
    }

  property("generate a valid signature for a p2wsh(p2pk) witness transaction") =
    Prop.forAllNoShrink(TransactionGenerators.signedP2WSHP2PKTransaction) { case (wtxSigComponent, privKeys) =>
      val program = ScriptProgram(wtxSigComponent)
      val result = ScriptInterpreter.run(program)
      result == ScriptOk
    }

  property("generate a valid signature for a p2wsh(p2pkh) witness transaction") =
    Prop.forAllNoShrink(TransactionGenerators.signedP2WSHP2PKHTransaction) { case (wtxSigComponent, privKeys) =>
      val program = ScriptProgram(wtxSigComponent)
      val result = ScriptInterpreter.run(program)
      result == ScriptOk
    }

  property("generate a valid signature for a p2wsh(multisig) witness transaction") =
    Prop.forAllNoShrink(TransactionGenerators.signedP2WSHMultiSigTransaction) { case (wtxSigComponent, privKeys) =>
      val program = ScriptProgram(wtxSigComponent)
      val result = ScriptInterpreter.run(program)
      if (result != ScriptOk) logger.warn("Result: " + result)
      Seq(ScriptErrorPushSize, ScriptOk).contains(result)
    }

  property("generate a valid signature from a p2sh(p2wpkh) witness transaction") =
    Prop.forAllNoShrink(TransactionGenerators.signedP2SHP2WPKHTransaction) { case (wtxSigComponent, privKeys) =>
      val program = ScriptProgram(wtxSigComponent)
      val result = ScriptInterpreter.run(program)
      if (result != ScriptOk) logger.warn("Result: " + result)
      result == ScriptOk
    }

  property("generate a valid signature from a p2sh(p2wsh) witness tranasction") =
    Prop.forAllNoShrink(TransactionGenerators.signedP2SHP2WSHTransaction) { case (wtxSigComponent, privKeys) =>
      val program = ScriptProgram(wtxSigComponent)
      val result = ScriptInterpreter.run(program)
      if (result != ScriptOk) logger.warn("Result: " + result)
      Seq(ScriptErrorPushSize, ScriptOk).contains(result)
    }

  property("generate a valid withdrawl tx from a sidechain") =
    Prop.forAll(TransactionGenerators.withdrawlTransaction) { case (fPegSigComponent, privKeys) =>
      val program = ScriptProgram(fPegSigComponent)
      val result = ScriptInterpreter.run(program)
      if (result != ScriptOk) logger.error("Script result: " + result)
      result == ScriptOk
    }
}
