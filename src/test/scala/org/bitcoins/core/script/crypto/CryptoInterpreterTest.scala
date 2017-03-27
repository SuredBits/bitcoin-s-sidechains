package org.bitcoins.core.script.crypto

import org.bitcoins.core.config.TestNet3
import org.bitcoins.core.crypto.{DoubleSha256Digest, FedPegTransactionSignatureComponent, Sha256Hash160Digest, WitnessV0TransactionSignatureComponent}
import org.bitcoins.core.currency.{CurrencyUnits, Satoshis}
import org.bitcoins.core.gen.{CryptoGenerators, MerkleGenerator, ScriptGenerators, TransactionGenerators}
import org.bitcoins.core.number.{Int64, UInt32}
import org.bitcoins.core.policy.Policy
import org.bitcoins.core.protocol.blockchain.TestNetChainParams
import org.bitcoins.core.protocol.script._
import org.bitcoins.core.protocol.transaction._
import org.bitcoins.core.script._
import org.bitcoins.core.script.constant._
import org.bitcoins.core.script.flag.{ScriptFlagFactory, ScriptVerifyDerSig, ScriptVerifyNullDummy}
import org.bitcoins.core.script.interpreter.ScriptInterpreter
import org.bitcoins.core.script.result._
import org.bitcoins.core.script.stack.OP_DROP
import org.bitcoins.core.util._
import org.scalatest.{FlatSpec, MustMatchers}

/**
 * Created by chris on 1/6/16.
 */
class CryptoInterpreterTest extends FlatSpec with MustMatchers with CryptoInterpreter with BitcoinSLogger {
  val stack = List(ScriptConstant("02218AD6CDC632E7AE7D04472374311CEBBBBF0AB540D2D08C3400BB844C654231".toLowerCase))

  "CryptoInterpreter" must "evaluate OP_HASH160 correctly when it is on top of the script stack" in {

    val script = List(OP_HASH160)
    val program = ScriptProgram(TestUtil.testProgram, stack,script)
    val newProgram = opHash160(program)

    newProgram.stack.head must be (ScriptConstant("5238C71458E464D9FF90299ABCA4A1D7B9CB76AB".toLowerCase))
    newProgram.script.size must be (0)
  }

  it must "mark the script as invalid when there are no arguments for OP_HASH160" in {
    val stack = List()
    val script = List(OP_HASH160)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack,script)
    val executedProgram : ExecutedScriptProgram = ScriptProgramTestUtil.toExecutedScriptProgram(opHash160(program))
    executedProgram.error must be (Some(ScriptErrorInvalidStackOperation))

  }

  it must "fail to evaluate OP_HASH160 when the script stack is empty" in {
    intercept[IllegalArgumentException] {
      val script = List()
      val program = ScriptProgram(TestUtil.testProgram, stack,script)
      opHash160(program)
    }
  }

  it must "evaluate an OP_RIPEMD160 correctly" in {
    val stack = List(ScriptConstant(""))
    val script = List(OP_RIPEMD160)
    val program = ScriptProgram(TestUtil.testProgram, stack,script)
    val newProgram = opRipeMd160(program)
    newProgram.stack must be (List(ScriptConstant("9c1185a5c5e9fc54612808977ee8f548b2258d31")))
    newProgram.script.isEmpty must be (true)
  }

  it must "evaluate a OP_SHA1 correctly" in {
    val stack = List(ScriptConstant("ab"))
    val script = List(OP_SHA1)
    val program = ScriptProgram(TestUtil.testProgram, stack,script)
    val newProgram = opSha1(program)
    newProgram.stack.head must be (ScriptConstant("fe83f217d464f6fdfa5b2b1f87fe3a1a47371196"))
    newProgram.script.isEmpty must be (true)
  }

  it must "evaluate an OP_SHA256 correctly" in {
    val stack = List(ScriptConstant(""))
    val script = List(OP_SHA256)
    val program = ScriptProgram(TestUtil.testProgram, stack,script)
    val newProgram = opSha256(program)
    newProgram.stack must be (List(ScriptConstant("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")))
    newProgram.script.isEmpty must be (true)
  }

  it must "evaluate an OP_HASH256 correctly" in {
    val stack = List(ScriptConstant(""))
    val script = List(OP_HASH256)
    val program = ScriptProgram(TestUtil.testProgram, stack,script)
    val newProgram = opHash256(program)
    newProgram.stack must be (List(ScriptConstant("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")))
    newProgram.script.isEmpty must be (true)
  }

  it must "evaluate an OP_CHECKMULTISIG with zero signatures and zero pubkeys" in {
    val stack = List(OP_0,OP_0,OP_0)
    val script = List(OP_CHECKMULTISIG)
    val program = ScriptProgram(TestUtil.testProgram, stack,script)
    val programNoFlags = ScriptProgram(program, ScriptFlagFactory.empty)
    val newProgram = opCheckMultiSig(programNoFlags)
    newProgram.stack must be (List(OP_TRUE))
    newProgram.script.isEmpty must be (true)
  }

  it must "evaluate an OP_CHECKMULTISIG and leave the remaining operations on the stack" in {
    val stack = List(OP_0,OP_0,OP_0, OP_16,OP_16,OP_16)
    val script = List(OP_CHECKMULTISIG,OP_16,OP_16,OP_16,OP_16)
    val program = ScriptProgram(TestUtil.testProgram, stack,script)
    val programNoFlags = ScriptProgram(program, ScriptFlagFactory.empty)
    val newProgram = opCheckMultiSig(programNoFlags)
    newProgram.stack must be (List(OP_TRUE, OP_16,OP_16,OP_16))
    newProgram.script must be (List(OP_16,OP_16,OP_16,OP_16))
  }

  it must "evaluate an OP_CHECKMULTISIGVERIFY with zero signatures and zero pubkeys" in {
    val stack = List(ScriptNumber.zero,ScriptNumber.zero,ScriptNumber.zero)
    val script = List(OP_CHECKMULTISIGVERIFY)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack,script)
    val programNoFlags = ScriptProgram(program, ScriptFlagFactory.empty)
    val newProgram = opCheckMultiSigVerify(programNoFlags)
    println(newProgram.script)
    newProgram.script.isEmpty must be (true)
    newProgram.stack.isEmpty must be (true)
    newProgram.isInstanceOf[ExecutedScriptProgram] must be (false)
  }

 it must "evaluate an OP_CHECKMULTISIGVERIFY and leave the remaining operations on the stack" in {
    val stack = List(OP_0,OP_0,OP_0, OP_16,OP_16,OP_16)
    val script = List(OP_CHECKMULTISIGVERIFY,OP_16,OP_16,OP_16,OP_16)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress, stack,script)
    val programNoFlags = ScriptProgram(program, ScriptFlagFactory.empty)
    val newProgram = opCheckMultiSigVerify(programNoFlags)
    newProgram.stack must be (List(OP_16,OP_16,OP_16))
    newProgram.script must be (List(OP_16,OP_16,OP_16,OP_16))
    newProgram.isInstanceOf[ExecutedScriptProgram] must be (false)
  }

  it must "evaluate an OP_CHECKMULTISIG for" in {
    //0 0 0 1 CHECKMULTISIG VERIFY DEPTH 0 EQUAL
    val stack = List(OP_1,OP_0,OP_0,OP_0)
    val script = List(OP_CHECKMULTISIG)
    val program = ScriptProgram(TestUtil.testProgram, stack,script)
    val programNoFlags = ScriptProgram(program, ScriptFlagFactory.empty)
    logger.warn("Running OP_CHECKMULTISIG program")
    val newProgram = opCheckMultiSig(programNoFlags)
    logger.warn("Ran OP_CHECKMULTISIG program")
    newProgram.stack must be (List(OP_TRUE))
    newProgram.script.isEmpty must be (true)
    newProgram.isInstanceOf[ExecutedScriptProgram] must be (false)
  }

  it must "mark a transaction invalid when the NULLDUMMY flag is set for a OP_CHECKMULTISIG operation & the scriptSig does not begin with OP_0" in {
    val flags = Seq(ScriptVerifyNullDummy)
    val scriptSig = ScriptSignature.fromAsm(Seq(OP_1))
    val input = TransactionInput(EmptyTransactionOutPoint, scriptSig, TransactionConstants.sequence)
    val tx = Transaction(TestUtil.transaction,UpdateTransactionInputs(Seq(input)))

    val baseProgram = ScriptProgram.toExecutionInProgress(ScriptProgram(tx,TestUtil.scriptPubKey,
      UInt32.zero,flags))
    val stack = Seq(OP_0,OP_0,OP_1)
    val script = Seq(OP_CHECKMULTISIG)
    val program = ScriptProgram(baseProgram,stack,script)
    val executedProgram = opCheckMultiSig(program)
    val newProgram = ScriptProgramTestUtil.toExecutedScriptProgram(executedProgram)
    newProgram.error must be (Some(ScriptErrorSigNullDummy))

  }

  it must "mark a transaction invalid when the DERSIG flag is set for a OP_CHECKSIG operaetion & the signature is not a strict der sig" in {
    val flags = Seq(ScriptVerifyDerSig)
    //signature is from script_valid.json, it has a negative S value which makes it non strict der
    val stack = Seq(OP_0,ScriptConstant("302402107777777777777777777777777777777702108777777777777777777777777777777701"))
    val script = Seq(OP_CHECKSIG)
    val program = ScriptProgram(TestUtil.testProgramExecutionInProgress,stack,script)
    val programWithFlags = ScriptProgram(program,flags)
    val newProgram = ScriptProgramTestUtil.toExecutedScriptProgram(opCheckSig(programWithFlags))
    newProgram.error must be (Some(ScriptErrorSigDer))

  }

  it must "evaluate an OP_CODESEPARATOR" in {
    val stack = List()
    val script = Seq(OP_CODESEPARATOR)
    val program = ScriptProgram(ScriptProgram(TestUtil.testProgramExecutionInProgress,stack,script),script,ScriptProgram.OriginalScript)
    val newProgram = ScriptProgramTestUtil.toExecutionInProgressScriptProgram(opCodeSeparator(program))
    newProgram.lastCodeSeparator must be (Some(0))
  }

  it must "verify an attempt to withdraw coins from a blockchain" in {
    // 1. genesis block hash of the chain the withdraw is coming from
    // 2. the index within the locking tx's outputs we are claiming
    // 3. the locking tx itself, this is the locking tx on the mainchain, not the relocking tx on sidechain (WithdrawProofReadStackItem)
    // 4. the merkle block structure which contains the block in which
    //    the locking transaction is present (WithdrawProofReadStackItem)
    // 5. The contract which we are expected to send coins to

    //genesis block hash on the chain we are pegged to (bitcoin regtest chain in this case)
    val genesisBlockHash = DoubleSha256Digest("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f")

    val inputIndex = UInt32.zero
    val usersHash = Sha256Hash160Digest("d76885e2754fcd108c0204eab323e071e24e9a98")
    val contract: Seq[Byte] = BitcoinSUtil.decodeHex("5032504800000000000000000000000000000000") ++ usersHash.bytes
    val amount = Satoshis(Int64(500))
    //note: this has the pushop on the front for the script which elements does not have
    val fedPegScript = ScriptPubKey("255121025015a9e8e8831cf859e314b5a6a283d8fd6d201ba6aa8c7d20453dfd12fa2bea51ae")
    val lockingScriptPubKey: ScriptPubKey = P2SHScriptPubKey(fedPegScript)
    val lockingOutput: TransactionOutput = TransactionOutput(amount,lockingScriptPubKey)
    val lockTx = buildLockingTx(lockingOutput)
    //TODO: This will fail to generate every now and then because generating a merkle block is expensive
    val (merkleBlock,_,_) = MerkleGenerator.merkleBlockWithInsertedTxIds(Seq(lockTx)).sample.get

    val (sidechainCreditingTx,outputIndex) = buildSidechainCreditingTx(genesisBlockHash)
    val sidechainCreditingOutput = sidechainCreditingTx.outputs(outputIndex)
    val sidechainUserOutput = TransactionOutput(amount,P2PKHScriptPubKey(usersHash))
    val relockScriptPubKey = WithdrawScriptPubKey(DoubleSha256Digest(genesisBlockHash.bytes))
    val relockAmount = sidechainCreditingOutput.value - amount
    val sidechainFederationRelockOutput = TransactionOutput(relockAmount, relockScriptPubKey)
    val sidechainReceivingTx = Transaction(TransactionConstants.version,Seq(TransactionGenerators.input.sample.get),
      Seq(sidechainUserOutput, sidechainFederationRelockOutput), TransactionConstants.lockTime)

    val wtxSigComponent = WitnessV0TransactionSignatureComponent(sidechainReceivingTx,inputIndex, sidechainCreditingOutput,
      Policy.standardScriptVerifyFlags, SigVersionWitnessV0)
    val fPegSigComponent = FedPegTransactionSignatureComponent(wtxSigComponent,fedPegScript)
    val stack: Seq[ScriptToken] = Seq(ScriptConstant(genesisBlockHash.bytes), ScriptNumber.zero,
      ScriptConstant(lockTx.bytes), ScriptConstant(merkleBlock.bytes), ScriptConstant(contract))
    val script: Seq[ScriptToken] = Seq(OP_WITHDRAWPROOFVERIFY)

    val program = ScriptProgram(ScriptProgram(fPegSigComponent), stack, script)

    val newProgram = opWithdrawProofVerify(program)

    newProgram.isInstanceOf[ExecutedScriptProgram] must be (false)
    newProgram.script must be (Nil)
    newProgram.stack must be (stack)
  }

  it must "fail to verify an attempt to withdraw coins from a blockchain if we do not have a valid relock script" in {
    // 1. genesis block hash of the chain the withdraw is coming from
    // 2. the index within the locking tx's outputs we are claiming
    // 3. the locking tx itself, this is the locking tx on the mainchain, not the relocking tx on sidechain (WithdrawProofReadStackItem)
    // 4. the merkle block structure which contains the block in which
    //    the locking transaction is present (WithdrawProofReadStackItem)
    // 5. The contract which we are expected to send coins to

    //genesis block hash on the chain we are pegged to (bitcoin regtest chain in this case)
    val genesisBlockHash = DoubleSha256Digest("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f")

    val inputIndex = UInt32.zero

    val contract: Seq[Byte] = BitcoinSUtil.decodeHex("5032504800000000000000000000000000000000d76885e2754fcd108c0204eab323e071e24e9a98")
    val amount = Satoshis(Int64(500))
    //note: this has the pushop on the front for the script which elements does not have
    val fedPegScript = ScriptPubKey("255121025015a9e8e8831cf859e314b5a6a283d8fd6d201ba6aa8c7d20453dfd12fa2bea51ae")
    val lockingScriptPubKey: ScriptPubKey = P2SHScriptPubKey(fedPegScript)
    val lockingOutput: TransactionOutput = TransactionOutput(amount,lockingScriptPubKey)
    val lockTx = buildLockingTx(lockingOutput)
    //TODO: This will fail to generate every now and then because generating a merkle block is expensive
    val (merkleBlock,_,_) = MerkleGenerator.merkleBlockWithInsertedTxIds(Seq(lockTx)).sample.get

    val (sidechainCreditingTx,outputIndex) = buildSidechainCreditingTx(genesisBlockHash)
    val sidechainCreditingOutput = sidechainCreditingTx.outputs(outputIndex)
    val sidechainOutput = TransactionOutput(amount,P2PKHScriptPubKey(Sha256Hash160Digest("d76885e2754fcd108c0204eab323e071e24e9a98")))
    val sidechainReceivingTx = Transaction(TransactionConstants.version,Seq(TransactionGenerators.input.sample.get),
      Seq(sidechainOutput), TransactionConstants.lockTime)

    val wtxSigComponent = WitnessV0TransactionSignatureComponent(sidechainReceivingTx,inputIndex, sidechainCreditingOutput,
      Policy.standardScriptVerifyFlags, SigVersionWitnessV0)
    val fPegSigComponent = FedPegTransactionSignatureComponent(wtxSigComponent,fedPegScript)
    val stack: Seq[ScriptToken] = Seq(ScriptConstant(genesisBlockHash.bytes), ScriptNumber.zero,
      ScriptConstant(lockTx.bytes), ScriptConstant(merkleBlock.bytes), ScriptConstant(contract))
    val script: Seq[ScriptToken] = Seq(OP_WITHDRAWPROOFVERIFY)

    val program = ScriptProgram(ScriptProgram(fPegSigComponent), stack, script)

    val newProgram = opWithdrawProofVerify(program)

    newProgram.isInstanceOf[ExecutedScriptProgram] must be (true)
    val errorProgram = newProgram.asInstanceOf[ExecutedScriptProgram]
    errorProgram.error must be (Some(ScriptErrorWithdrawVerifyRelockScriptVal))
  }


  private def buildLockingTx(lockingOutput: TransactionOutput): Transaction = {
    val randomInput: TransactionInput = TransactionGenerators.input.sample.get
    Transaction(TransactionConstants.version,Seq(randomInput), Seq(lockingOutput), TransactionConstants.lockTime)
  }

  /** Builds the crediting OP_WPV and the output index it is located at */
  private def buildSidechainCreditingTx(genesisBlockHash: DoubleSha256Digest): (Transaction,Int) = {
    val scriptPubKey = ScriptPubKey.fromAsm(Seq(BytesToPushOntoStack(32),
      ScriptConstant(genesisBlockHash.bytes), OP_WITHDRAWPROOFVERIFY))
    val amount = Satoshis(Int64(1000))
    val outputs = Seq(TransactionOutput(amount,scriptPubKey))
    val inputs = Seq(TransactionGenerators.input.sample.get)
    (Transaction(TransactionConstants.version,inputs,outputs,TransactionConstants.lockTime),0)
  }
}
