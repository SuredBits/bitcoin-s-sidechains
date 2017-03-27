package org.bitcoins.core.crypto

import org.bitcoins.core.crypto.WitnessV0TransactionSignatureComponent.WitnessV0TransactionSignatureComponentImpl
import org.bitcoins.core.currency.CurrencyUnit
import org.bitcoins.core.number.UInt32
import org.bitcoins.core.protocol.script._
import org.bitcoins.core.protocol.transaction.{BaseTransaction, Transaction, TransactionOutput, WitnessTransaction}
import org.bitcoins.core.script.constant.ScriptToken
import org.bitcoins.core.script.flag.ScriptFlag

import scala.annotation.tailrec

/**
 * Created by chris on 4/6/16.
 * Represents a transaction whose input is being checked against the spending conditions of the
 * scriptPubKey
 */
sealed trait TransactionSignatureComponent {

  /** The transaction being checked for the validity of signatures */
  def transaction : Transaction

  /** The index of the input whose script signature is being checked */
  def inputIndex : UInt32

  /** The script signature being checked */
  def scriptSignature = transaction.inputs(inputIndex.toInt).scriptSignature

  /** The scriptPubKey for which the input is being checked against */
  def scriptPubKey : ScriptPubKey

  /** The flags that are needed to verify if the signature is correct*/
  def flags : Seq[ScriptFlag]

  /** Represents the serialization algorithm used to verify/create signatures for Bitcoin */
  def sigVersion: SignatureVersion
}

/** The [[TransactionSignatureComponent]] used to evaluate the the original Satoshi transaction digest algorithm */
sealed trait BaseTransactionSignatureComponent extends TransactionSignatureComponent {
  override def sigVersion = SigVersionBase
}

/** The [[TransactionSignatureComponent]] used to represent all the components necessarily for BIP143
  * [[https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki]]
  */
sealed trait WitnessV0TransactionSignatureComponent extends TransactionSignatureComponent {

  def witness: ScriptWitness = transaction match {
    case wtx: WitnessTransaction => wtx.witness.witnesses(inputIndex.toInt)
    case btx: BaseTransaction => EmptyScriptWitness
  }

  /** The amount of [[CurrencyUnit]] this input is spending */
  def amount: CurrencyUnit

}

sealed trait FedPegTransactionSignatureComponent extends TransactionSignatureComponent {
  def witnessTxSigComponent: WitnessV0TransactionSignatureComponent
  def fedPegScript: ScriptPubKey


  override def flags = witnessTxSigComponent.flags
  override def inputIndex = witnessTxSigComponent.inputIndex
  override def scriptPubKey = witnessTxSigComponent.scriptPubKey
  override def sigVersion = witnessTxSigComponent.sigVersion
  override def transaction = witnessTxSigComponent.transaction

  /** Grabs the [[TransactionOutput]] that is offset from the given inputIndex */
  def getOutputOffSetFromCurrent(offset: Int): Option[TransactionOutput] = {
    require(witnessTxSigComponent.inputIndex >= UInt32.zero && witnessTxSigComponent.transaction.outputs.size > 0)
    val c = witnessTxSigComponent
    val tx = witnessTxSigComponent.transaction
    val inputIndex = c.inputIndex.toInt
    val outputSize = c.transaction.outputs.size
    if (inputIndex + offset < 0 || outputSize <= (inputIndex + offset)) {
      None
    } else {
      Some(transaction.outputs(inputIndex + offset))
    }
  }
}

object TransactionSignatureComponent {

  private case class BaseTransactionSignatureComponentImpl(transaction : Transaction, inputIndex : UInt32,
                                                       scriptPubKey : ScriptPubKey, flags : Seq[ScriptFlag]) extends BaseTransactionSignatureComponent


  def apply(transaction : Transaction, inputIndex : UInt32, scriptPubKey : ScriptPubKey,
            flags : Seq[ScriptFlag], amount: CurrencyUnit, signatureVersion: SignatureVersion) : TransactionSignatureComponent = {
    signatureVersion match {
      case SigVersionBase =>
        TransactionSignatureComponent(transaction,inputIndex,scriptPubKey,flags)
      case SigVersionWitnessV0 =>
        WitnessV0TransactionSignatureComponent(transaction,inputIndex,scriptPubKey,flags,amount,signatureVersion)
    }

  }

  def apply(transaction : Transaction, inputIndex : UInt32,
            scriptPubKey : ScriptPubKey, flags : Seq[ScriptFlag]): BaseTransactionSignatureComponent = {
    BaseTransactionSignatureComponentImpl(transaction,inputIndex,scriptPubKey,flags)
  }

  /** This factory method is used for changing the scriptPubKey inside of a txSignatureComponent */
  def apply(oldTxSignatureComponent : TransactionSignatureComponent, scriptPubKey : ScriptPubKey) : TransactionSignatureComponent = oldTxSignatureComponent match {
    case base: BaseTransactionSignatureComponent =>
    TransactionSignatureComponent(base.transaction,
      base.inputIndex,scriptPubKey, base.flags)
    case w: WitnessV0TransactionSignatureComponent =>
      TransactionSignatureComponent(w.transaction,w.inputIndex,scriptPubKey,w.flags,w.amount,w.sigVersion)
    case f : FedPegTransactionSignatureComponent =>
      FedPegTransactionSignatureComponent(f.transaction,f.inputIndex,scriptPubKey,f.flags,
        f.witnessTxSigComponent.amount, f.witnessTxSigComponent.sigVersion, f.fedPegScript)
  }
}

object WitnessV0TransactionSignatureComponent {
  private case class WitnessV0TransactionSignatureComponentImpl(transaction : Transaction, inputIndex : UInt32,
                                                                scriptPubKey : ScriptPubKey, flags : Seq[ScriptFlag],
                                                                amount: CurrencyUnit, sigVersion: SignatureVersion) extends WitnessV0TransactionSignatureComponent

  def apply(transaction : Transaction, inputIndex : UInt32, scriptPubKey : ScriptPubKey,
            flags : Seq[ScriptFlag], amount: CurrencyUnit, sigVersion: SignatureVersion) : WitnessV0TransactionSignatureComponent = {
    WitnessV0TransactionSignatureComponentImpl(transaction,inputIndex, scriptPubKey, flags, amount,sigVersion)
  }

  /** Note: The output passed here is the output we are spending,
    * we use the [[CurrencyUnit]] and [[ScriptPubKey]] in that output for signing */
  def apply(transaction : Transaction, inputIndex : UInt32, output : TransactionOutput,
            flags : Seq[ScriptFlag], sigVersion: SignatureVersion): WitnessV0TransactionSignatureComponent = {
    WitnessV0TransactionSignatureComponent(transaction,inputIndex,output.scriptPubKey,flags,output.value, sigVersion)
  }
}

object FedPegTransactionSignatureComponent {
  private case class FedPegTransactionSignatureComponentImpl(witnessTxSigComponent: WitnessV0TransactionSignatureComponent,
                                                             fedPegScript: ScriptPubKey) extends FedPegTransactionSignatureComponent


  def apply(witnessTxSigComponent : WitnessV0TransactionSignatureComponent,
            fedPegScript: ScriptPubKey): FedPegTransactionSignatureComponent = {
    FedPegTransactionSignatureComponentImpl(witnessTxSigComponent,fedPegScript)
  }

  def apply(transaction : Transaction, inputIndex : UInt32, scriptPubKey : ScriptPubKey,
            flags : Seq[ScriptFlag], amount: CurrencyUnit, sigVersion: SignatureVersion, fedPegScript: ScriptPubKey) : FedPegTransactionSignatureComponent = {
    val w = WitnessV0TransactionSignatureComponent(transaction,inputIndex,scriptPubKey,flags,amount,sigVersion)
    FedPegTransactionSignatureComponentImpl(w,fedPegScript)
  }
}