package org.bitcoins.core.script.crypto

import org.bitcoins.core.crypto._
import org.bitcoins.core.currency.CurrencyUnits
import org.bitcoins.core.protocol.blockchain.MerkleBlock
import org.bitcoins.core.protocol.script._
import org.bitcoins.core.protocol.transaction.{EmptyTransactionOutput, Transaction, TransactionOutput}
import org.bitcoins.core.script.{ScriptProgram, _}
import org.bitcoins.core.script.constant._
import org.bitcoins.core.script.control.{ControlOperationsInterpreter, OP_VERIFY}
import org.bitcoins.core.script.flag.{ScriptFlagUtil, ScriptVerifyWithdraw}
import org.bitcoins.core.script.result._
import org.bitcoins.core.util.{BitcoinSLogger, BitcoinScriptUtil, CryptoUtil}

import scala.annotation.tailrec
import scala.util.Try


/**
 * Created by chris on 1/6/16.
 */
trait CryptoInterpreter extends ControlOperationsInterpreter with BitcoinSLogger {

  /** The input is hashed twice: first with SHA-256 and then with RIPEMD-160. */
  def opHash160(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_HASH160), "Script operation must be OP_HASH160")
    executeHashFunction(program, CryptoUtil.sha256Hash160(_ : Seq[Byte]))
  }

  /** The input is hashed using RIPEMD-160. */
  def opRipeMd160(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_RIPEMD160), "Script operation must be OP_RIPEMD160")
    executeHashFunction(program, CryptoUtil.ripeMd160(_ : Seq[Byte]))
  }

  /** The input is hashed using SHA-256. */
  def opSha256(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_SHA256), "Script operation must be OP_SHA256")
    executeHashFunction(program, CryptoUtil.sha256(_ : Seq[Byte]))
  }

  /** The input is hashed two times with SHA-256. */
  def opHash256(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_HASH256), "Script operation must be OP_HASH256")
    executeHashFunction(program, CryptoUtil.doubleSHA256(_ : Seq[Byte]))
  }

  /** The input is hashed using SHA-1. */
  def opSha1(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_SHA1), "Script top must be OP_SHA1")
    executeHashFunction(program, CryptoUtil.sha1(_ : Seq[Byte]))
  }

  /**
   * The entire transaction's outputs, inputs, and script (from the most
   * recently-executed OP_CODESEPARATOR to the end) are hashed.
   * The signature used by [[OP_CHECKSIG]] must be a valid signature for this hash and public key.
   * [[https://github.com/bitcoin/bitcoin/blob/528472111b4965b1a99c4bcf08ac5ec93d87f10f/src/script/interpreter.cpp#L880]]
   */
  def opCheckSig(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_CHECKSIG), "Script top must be OP_CHECKSIG")
    program match {
      case preExecutionScriptProgram : PreExecutionScriptProgram =>
        opCheckSig(ScriptProgram.toExecutionInProgress(preExecutionScriptProgram))
      case executedScriptprogram : ExecutedScriptProgram =>
        executedScriptprogram
      case executionInProgressScriptProgram : ExecutionInProgressScriptProgram =>
        if (executionInProgressScriptProgram.stack.size < 2) {
          logger.error("OP_CHECKSIG requires at lest two stack elements")
          ScriptProgram(program,ScriptErrorInvalidStackOperation)
        } else {
          val pubKey = ECPublicKey(executionInProgressScriptProgram.stack.head.bytes)
          val signature = ECDigitalSignature(executionInProgressScriptProgram.stack.tail.head.bytes)
          val flags = executionInProgressScriptProgram.flags
          val restOfStack = executionInProgressScriptProgram.stack.tail.tail
          logger.debug("Program before removing OP_CODESEPARATOR: " + program.originalScript)
          val removedOpCodeSeparatorsScript = BitcoinScriptUtil.removeOpCodeSeparator(executionInProgressScriptProgram)
          logger.debug("Program after removing OP_CODESEPARATOR: " + removedOpCodeSeparatorsScript)
          val result = TransactionSignatureChecker.checkSignature(executionInProgressScriptProgram.txSignatureComponent,
            removedOpCodeSeparatorsScript, pubKey, signature, flags)
          handleSignatureValidation(program,result,restOfStack)
        }
    }
  }

  /** Runs [[OP_CHECKSIG]] with an [[OP_VERIFY]] afterwards. */
  def opCheckSigVerify(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_CHECKSIGVERIFY),
      "Script top must be OP_CHECKSIGVERIFY")
    if (program.stack.size < 2) {
      logger.error("Stack must contain at least 3 items for OP_CHECKSIGVERIFY")
      ScriptProgram(program,ScriptErrorInvalidStackOperation)
    } else {
      val newScript = OP_CHECKSIG :: OP_VERIFY :: program.script.tail
      val newProgram = ScriptProgram(program,newScript, ScriptProgram.Script)
      val programFromOpCheckSig = opCheckSig(newProgram)
      logger.debug("Stack after OP_CHECKSIG execution: " + programFromOpCheckSig.stack)
      programFromOpCheckSig match {
        case _ : PreExecutionScriptProgram | _ : ExecutedScriptProgram =>
          programFromOpCheckSig
        case _ : ExecutionInProgressScriptProgram => opVerify(programFromOpCheckSig)
      }
    }
  }
  
  /** All of the signature checking words will only match signatures to the data
   * after the most recently-executed [[OP_CODESEPARATOR]]. */
  def opCodeSeparator(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_CODESEPARATOR), "Script top must be OP_CODESEPARATOR")
    val e = program match {
      case e : PreExecutionScriptProgram =>
        opCodeSeparator(ScriptProgram.toExecutionInProgress(e))
      case e : ExecutionInProgressScriptProgram =>
        val indexOfOpCodeSeparator = program.originalScript.size - program.script.size
        ScriptProgram(e,program.script.tail,ScriptProgram.Script,indexOfOpCodeSeparator)
      case e : ExecutedScriptProgram =>
        ScriptProgram(e,ScriptErrorUnknownError)
    }
    e
  }

  /**
    * Compares the first signature against each public key until it finds an ECDSA match.
    * Starting with the subsequent public key, it compares the second signature against each remaining
    * public key until it finds an ECDSA match. The process is repeated until all signatures have been
    * checked or not enough public keys remain to produce a successful result.
    * All signatures need to match a public key.
    * Because public keys are not checked again if they fail any signature comparison,
    * signatures must be placed in the scriptSig using the same order as their corresponding public keys
    * were placed in the scriptPubKey or redeemScript. If all signatures are valid, 1 is returned, 0 otherwise.
    * Due to a bug, one extra unused value is removed from the stack.
    */
  @tailrec
  final def opCheckMultiSig(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_CHECKMULTISIG), "Script top must be OP_CHECKMULTISIG")
    val flags = program.flags
    program match {
      case preExecutionScriptProgram : PreExecutionScriptProgram =>
        opCheckMultiSig(ScriptProgram.toExecutionInProgress(preExecutionScriptProgram))
      case executedScriptProgram : ExecutedScriptProgram =>
        executedScriptProgram
      case executionInProgressScriptProgram : ExecutionInProgressScriptProgram =>
        if (program.stack.size < 1) {
          logger.error("OP_CHECKMULTISIG requires at least 1 stack elements")
          ScriptProgram(executionInProgressScriptProgram,ScriptErrorInvalidStackOperation)
        } else {
          //these next lines remove the appropriate stack/script values after the signatures have been checked
          val nPossibleSignatures : ScriptNumber = BitcoinScriptUtil.numPossibleSignaturesOnStack(program)
          if (nPossibleSignatures < ScriptNumber.zero) {
            logger.error("We cannot have the number of pubkeys in the script be negative")
            ScriptProgram(program,ScriptErrorPubKeyCount)
          } else if (ScriptFlagUtil.requireMinimalData(flags) && !nPossibleSignatures.isShortestEncoding) {
            logger.error("The required signatures and the possible signatures must be encoded as the shortest number possible")
            ScriptProgram(executionInProgressScriptProgram, ScriptErrorUnknownError)
          } else if (program.stack.size < 2) {
            logger.error("We need at least 2 operations on the stack")
            ScriptProgram(executionInProgressScriptProgram,ScriptErrorInvalidStackOperation)
          } else {
            val mRequiredSignatures: ScriptNumber = BitcoinScriptUtil.numRequiredSignaturesOnStack(program)

            if (ScriptFlagUtil.requireMinimalData(flags) && !mRequiredSignatures.isShortestEncoding) {
              logger.error("The required signatures val must be the shortest encoding as possible")
              return ScriptProgram(executionInProgressScriptProgram, ScriptErrorUnknownError)
            }

            if (mRequiredSignatures < ScriptNumber.zero) {
              logger.error("We cannot have the number of signatures specified in the script be negative")
              return ScriptProgram(executionInProgressScriptProgram, ScriptErrorSigCount)
            }
            logger.debug("nPossibleSignatures: " + nPossibleSignatures)
            val (pubKeysScriptTokens, stackWithoutPubKeys) =
              (program.stack.tail.slice(0, nPossibleSignatures.toInt),
                program.stack.tail.slice(nPossibleSignatures.toInt, program.stack.tail.size))

            val pubKeys = pubKeysScriptTokens.map(key => ECPublicKey(key.bytes))
            logger.debug("Public keys on the stack: " + pubKeys)
            logger.debug("Stack without pubkeys: " + stackWithoutPubKeys)
            logger.debug("mRequiredSignatures: " + mRequiredSignatures)

            //+1 is for the fact that we have the # of sigs + the script token indicating the # of sigs
            val signaturesScriptTokens = program.stack.tail.slice(nPossibleSignatures.toInt + 1,
              nPossibleSignatures.toInt + mRequiredSignatures.toInt + 1)
            val signatures = signaturesScriptTokens.map(token => ECDigitalSignature(token.bytes))
            logger.debug("Signatures on the stack: " + signatures)

            //this contains the extra Script OP that is required for OP_CHECKMULTISIG
            val stackWithoutPubKeysAndSignatures = stackWithoutPubKeys.tail.slice(mRequiredSignatures.toInt, stackWithoutPubKeys.tail.size)
            logger.debug("stackWithoutPubKeysAndSignatures: " + stackWithoutPubKeysAndSignatures)
            if (pubKeys.size > ScriptSettings.maxPublicKeysPerMultiSig) {
              logger.error("We have more public keys than the maximum amount of public keys allowed")
              ScriptProgram(executionInProgressScriptProgram, ScriptErrorPubKeyCount)
            } else if (signatures.size > pubKeys.size) {
              logger.error("We have more signatures than public keys inside OP_CHECKMULTISIG")
              ScriptProgram(executionInProgressScriptProgram, ScriptErrorSigCount)
            } else if (stackWithoutPubKeysAndSignatures.size < 1) {
              logger.error("OP_CHECKMULTISIG must have a remaining element on the stack afterk execution")
              //this is because of a bug in bitcoin core for the implementation of OP_CHECKMULTISIG
              //https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L966
              ScriptProgram(executionInProgressScriptProgram,ScriptErrorInvalidStackOperation)
            } else if (ScriptFlagUtil.requireNullDummy(flags) &&
              (stackWithoutPubKeysAndSignatures.nonEmpty && stackWithoutPubKeysAndSignatures.head.bytes.nonEmpty)) {
              logger.error("Script flag null dummy was set however the first element in the script signature was not an OP_0, stackWithoutPubKeysAndSignatures: " + stackWithoutPubKeysAndSignatures)
              ScriptProgram(executionInProgressScriptProgram,ScriptErrorSigNullDummy)
            } else {
              //remove the last OP_CODESEPARATOR
              val removedOpCodeSeparatorsScript = BitcoinScriptUtil.removeOpCodeSeparator(executionInProgressScriptProgram)
              val isValidSignatures: TransactionSignatureCheckerResult =
                TransactionSignatureChecker.multiSignatureEvaluator(executionInProgressScriptProgram.txSignatureComponent,
                  removedOpCodeSeparatorsScript, signatures,
                  pubKeys, flags, mRequiredSignatures.underlying)

              //remove the extra OP_0 (null dummy) for OP_CHECKMULTISIG from the stack
              val restOfStack = stackWithoutPubKeysAndSignatures.tail
              handleSignatureValidation(program,isValidSignatures,restOfStack)
            }
          }
        }
      }
    }

  /** Runs [[OP_CHECKMULTISIG]] with an [[OP_VERIFY]] afterwards */
  def opCheckMultiSigVerify(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_CHECKMULTISIGVERIFY), "Script top must be OP_CHECKMULTISIGVERIFY")
    if (program.stack.size < 3) {
      logger.error("Stack must contain at least 3 items for OP_CHECKMULTISIGVERIFY")
      ScriptProgram(program,ScriptErrorInvalidStackOperation)
    } else {
      val newScript = OP_CHECKMULTISIG :: OP_VERIFY :: program.script.tail
      val newProgram = ScriptProgram(program,newScript, ScriptProgram.Script)
      val programFromOpCheckMultiSig = opCheckMultiSig(newProgram)
      logger.debug("Stack after OP_CHECKMULTSIG execution: " + programFromOpCheckMultiSig.stack)
      programFromOpCheckMultiSig match {
        case _ : PreExecutionScriptProgram | _ : ExecutedScriptProgram =>
          programFromOpCheckMultiSig
        case _ : ExecutionInProgressScriptProgram => opVerify(programFromOpCheckMultiSig)
      }
    }
  }

  /**
    * This function is used to evaluate a SPV proof that the user sent
    * sidechain coins to an SPV locked output
    *
    * From the sidechains whitepaper:
    * When a user wants to transfer coins from the sidechain back to the parent chain, they do the same
    * thing as the original transfer: send the coins on the sidechain to an SPV-locked output, produce a
    * sufficient SPV proof that this was done, and use the proof to unlock a number of previously-locked
    * outputs with equal denomination on the parent chain
    *
    * Implementation in elements:
    * [[https://github.com/ElementsProject/elements/blob/elements-0.13.1/src/script/interpreter.cpp#L1419]]
    *
    * @param program
    * @return
    */
  def opWithdrawProofVerify(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption == Some(OP_WITHDRAWPROOFVERIFY), "Script operation is required to be OP_WITHDRAWPROOFVERIFY")
    if (program.stack.size >= 7) {
      return ScriptProgram(program,ScriptErrorInvalidStackOperation)
    }

    val genesisHashToken = program.stack.head

    if (genesisHashToken.bytes.size != 32) {
      return ScriptProgram(program,ScriptErrorWithdrawVerifyFormat)
    }

    val genesisHash = DoubleSha256Digest(genesisHashToken.bytes)

    //we need the amount of the output, which is contained inside FedPegTransactionSignatureComponent
    require(program.txSignatureComponent.isInstanceOf[FedPegTransactionSignatureComponent])
    val fPegTxSigComponent = program.txSignatureComponent.asInstanceOf[FedPegTransactionSignatureComponent]

    val relockScript: ScriptPubKey = WithdrawScriptPubKey(DoubleSha256Digest(genesisHashToken.bytes))

    //regular withdraw from the sidechain

    val outputIndex: Int = program.stack(1) match {
      case number : ScriptNumber => number.toInt
      case err @ (_: ScriptConstant | _ : ScriptOperation) =>
        throw new IllegalArgumentException("We expected a ScriptNumber for output index in OP_WITHDRAWPROOFVERIFY, got: " + err)
    }

    val lockTx: Transaction = program.stack(2) match {
      case txConstant: ScriptConstant => Transaction(txConstant.bytes)
      case scriptOp : ScriptOperation =>
        throw new IllegalArgumentException("We expect a ScriptConstant for lockTx in OP_WITHDRAWPROOFVERIFY, got: " + scriptOp)
    }

    val merkleBlock: MerkleBlock = program.stack(3) match {
      case merkleBlockConstant: ScriptConstant => MerkleBlock(merkleBlockConstant.bytes)
      case scriptOp: ScriptOperation =>
        throw new IllegalArgumentException("We expect a ScriptConstant for a MerkleBlock in OP_WITHDRAWPROOFVERIFY, got: " + scriptOp)
    }

    val contract: Try[Contract] = program.stack(4) match {
      case constant: ScriptConstant =>
        Try(Contract(constant.bytes))
      case scriptOp: ScriptOperation =>
        throw new IllegalArgumentException("We expect a constant for our contract in OP_WITHDRAWPROOFVERIFY, got: " + scriptOp)
    }

    val isValidPoW : Boolean = checkBitcoinProofOfWork(merkleBlock)

    if (!isValidPoW) {
      logger.error("Invalid proof of work on the given block")
      return ScriptProgram(program,ScriptErrorWithdrawVerifyBlock)
    }
    val blockHeader = merkleBlock.blockHeader
    val partialMerkleTree = merkleBlock.partialMerkleTree
    val matchedTxs: Seq[DoubleSha256Digest] = partialMerkleTree.extractMatches

    if (!partialMerkleTree.tree.value.contains(merkleBlock.blockHeader.merkleRootHash) || matchedTxs.length != 1) {
      logger.error("Same root value: " + (!partialMerkleTree.tree.value.contains(merkleBlock.blockHeader.merkleRootHash)))
      logger.error("Matched more than one tx: " + (matchedTxs.length != 1) + " matchedTxs length: " + matchedTxs.length)
      logger.error("Incorrect partial merkle tree root hash or matched more than one tx in merkle tree")
      return ScriptProgram(program,ScriptErrorWithdrawVerifyBlock)
    }

    //We disallow returns from the genesis block, allowing sidechains to
    //make genesis outputs spendable with a 21m initially-locked-to-btc
    //distributing transactions
    if (blockHeader.hash == genesisHash) {
      logger.error("Incorrect genesis block hash")
      return ScriptProgram(program, ScriptErrorWithdrawVerifyBlock)
    }

/*      CTransaction locktx;
    CDataStream locktxStream(vlockTx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_BITCOIN_BLOCK_OR_TX);
    locktxStream >> locktx;
    if (!locktxStream.empty())
      return set_error(serror, SCRIPT_ERR_WITHDRAW_VERIFY_LOCKTX);*/

    if (outputIndex < 0 || outputIndex >= lockTx.outputs.length) {
      logger.error("Incorrect output on the withdrawl locking tx, output index: " + outputIndex)
      return ScriptProgram(program, ScriptErrorWithdrawVerifyLockTx)
    }

    if (matchedTxs.head != lockTx.txId) {
      logger.error("Incorrect withdrawl locking tx ")
      return ScriptProgram(program, ScriptErrorWithdrawVerifyLockTx)
    }

    if (contract.isFailure) {
      logger.error("Incorrect withdrawl contract format")
      return ScriptProgram(program, ScriptErrorWithdrawVerifyFormat)
    }

    val scriptDestination: ScriptPubKey = fPegTxSigComponent.fedPegScript


    /**
    * This tool allows you to take a redeemScript as a template and,
    * using basic EC math, replace public keys with ones which are only
    * spendable by the original key's private key holder and which cryptographically
    * commit to the contract hash specified. In this way, it provides a transparent and
    * undetectable way of sending payments which commit to some data without adding extra data
    * to the chain. It does, however, require some small amount of out-of-band communication.
    * This implements the neccessary parts of appendix A of the sidechains whitepaper,
    * though it is generally useful in many other cases.
    * https://botbot.me/freenode/sidechains-dev/2017-03-07/?tz=America/Chicago
    * */
/*      {
      CScript::iterator sdpc = scriptDestination.begin();
      vector<unsigned char> vch;
      while (scriptDestination.GetOp(sdpc, opcodeTmp, vch))
      {
        assert((vch.size() == 33 && opcodeTmp < OP_PUSHDATA4) ||
          (opcodeTmp <= OP_16 && opcodeTmp >= OP_1) || opcodeTmp == OP_CHECKMULTISIG);
        if (vch.size() == 33)
        {
          unsigned char tweak[32];
          size_t pub_len = 33;
          unsigned char *pub_start = &(*(sdpc - pub_len));
          CHMAC_SHA256(pub_start, pub_len).Write(&vcontract[0], 40).Finalize(tweak);
          secp256k1_pubkey pubkey;
          assert(secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey, pub_start, pub_len) == 1);
          // If someone creates a tweak that makes this fail, they broke SHA256
          assert(secp256k1_ec_pubkey_tweak_add(secp256k1_ctx, &pubkey, tweak) == 1);
          assert(secp256k1_ec_pubkey_serialize(secp256k1_ctx, pub_start, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED) == 1);
          assert(pub_len == 33);
        }
      }
    }*/

    val expectedP2SH = P2SHScriptPubKey(scriptDestination)
    val lockedOutput = lockTx.outputs(outputIndex)
    if (lockedOutput.scriptPubKey != expectedP2SH) {
      logger.error("Incorrect withdrawl output script destination")
      logger.error("Expected p2sh: " + expectedP2SH)
      logger.error("Locked output scriptPubKey: " + lockedOutput.scriptPubKey)
      return ScriptProgram(program, ScriptErrorWithdrawVerifyOutputScriptDest)
    }

/*
    val contractWithoutNonce = contract.take(4) ++ contract.slice(20,contract.length)

    require(contractWithoutNonce.length == 24, "Contract must be 24 bytes in size after removing nonce")
*/

    // We check values by doing the following:

    // * Tx must relock at least <unlocked coins> - <locked-on-bitcoin coins>
    // * Tx must send at least the withdraw value to its P2SH withdraw, but may send more

    //not sure what this is
    //assert(locktx.vout[nlocktxOut].nValue.IsAmount()); // Its a SERIALIZE_BITCOIN_BLOCK_OR_TX
    val peginAmount = fPegTxSigComponent.witnessTxSigComponent.amount
    val withdrawlAmount = lockedOutput.value

/*    if (!checker.GetValueIn().IsAmount()) // Heh, you just destroyed coins
      return set_error(serror, SCRIPT_ERR_WITHDRAW_VERIFY_BLINDED_AMOUNTS);*/
    val lockValueRequired = peginAmount - withdrawlAmount

    if (lockValueRequired > CurrencyUnits.zero) {
      val newLockOutput: Option[TransactionOutput] = fPegTxSigComponent.getOutputOffSetFromCurrent(1)
/*      if (!newLockOutput.nValue.IsAmount())
        return set_error(serror, SCRIPT_ERR_WITHDRAW_VERIFY_BLINDED_AMOUNTS);*/
      if (newLockOutput.isEmpty || newLockOutput.get.scriptPubKey != relockScript ||
        newLockOutput.get.value < lockValueRequired) {
        logger.error("Incorrect withdrawl relock script, got: " + newLockOutput)
        logger.error("Expected relock script: " + relockScript)
        logger.error("Lock valued required: " + lockValueRequired)
        return ScriptProgram(program, ScriptErrorWithdrawVerifyRelockScriptVal)
      }
    }

    val withdrawOutput: TransactionOutput = fPegTxSigComponent.getOutputOffSetFromCurrent(0).get

/*      if (!withdrawOutput.nValue.IsAmount())
      return set_error(serror, SCRIPT_ERR_WITHDRAW_VERIFY_BLINDED_AMOUNTS);*/

    if (withdrawOutput.value < withdrawlAmount) {
      logger.error("Incorrect withdrawl amount")
      return ScriptProgram(program, ScriptErrorWithdrawVerifyOutputVal)
    }

    val expectedWithdrawScriptPubKey: ScriptPubKey = parseWithdrawScriptPubKey(contract.get)

    if (expectedWithdrawScriptPubKey != withdrawOutput.scriptPubKey) {
      logger.error("Incorrect withdrawl scriptPubKey")
      logger.error("Expected withdraw scriptPubKey: " + expectedWithdrawScriptPubKey)
      logger.error("Actual withdraw scriptPubKey: " + withdrawOutput.scriptPubKey)
      return ScriptProgram(program,ScriptErrorWithdrawVerifyOutputScript)
    }

/*
      #ifndef BITCOIN_SCRIPT_NO_CALLRPC
      if (GetBoolArg("-validatepegin", false) && !checker.IsConfirmedBitcoinBlock(genesishash, merkleBlock.header.GetHash(), flags & SCRIPT_VERIFY_INCREASE_CONFIRMATIONS_REQUIRED))
        return set_error(serror, SCRIPT_ERR_WITHDRAW_VERIFY_BLOCKCONFIRMED);
      #endif
*/
    // comment from elements project
    // In the make-withdraw case, reads the following from the stack:
    // 1. genesis block hash of the chain the withdraw is coming from
    // 2. the index within the locking tx's outputs we are claiming
    // 3. the locking tx itself (WithdrawProofReadStackItem)
    // 4. the merkle block structure which contains the block in which
    //    the locking transaction is present (WithdrawProofReadStackItem)
    // 5. The contract which we are expected to send coins to
    //
    // In the combine-outputs case, reads the following from the stack:
    // 1. genesis block hash of the chain the withdraw is coming from

    val newScript = program.script.tail

    ScriptProgram(program,newScript, ScriptProgram.Script)
  }


  /**
    * This function is used to evaluate an SPV proof that the output specified in this script is part of the
    * longest chain on the blockchain the sidechain is pegged with.
    * From the sidechains whitepaper:
    * When transferring coins into the sidechain a user wait for the contest period to expire.
    * This is a duration in which a newly-transferred
    * coin may not be spent on the sidechain. The purpose of a contest period is to prevent double-
    * spending by transferring previously-locked coins during a reorganisation. If at any point
    * during this delay, a new proof is published containing a chain with more aggregate work
    * which does not include the block in which the lock output was created, the conversion is
    * retroactively invalidated. We call this a reorganisation proof.
    *
    * Implementation in elements:
    * https://github.com/ElementsProject/elements/blob/alpha/src/script/interpreter.cpp#L1584
    *
    * @param program
    * @return
    */
  def opReorgProofVerify(program : ScriptProgram) : ScriptProgram = {
    //TODO: Implement this later
    ScriptProgram(program,program.script.tail, ScriptProgram.Script)
  }


  /**
   * This is a higher order function designed to execute a hash function on the stack top of the program
   * For instance, we could pass in CryptoUtil.sha256 function as the 'hashFunction' argument, which would then
   * apply sha256 to the stack top
    *
    * @param program the script program whose stack top needs to be hashed
   * @param hashFunction the hash function which needs to be used on the stack top (sha256,ripemd160,etc..)
   * @return
   */
  private def executeHashFunction(program : ScriptProgram, hashFunction : Seq[Byte] => HashDigest) : ScriptProgram = {
    if (program.stack.nonEmpty) {
      val stackTop = program.stack.head
      val hash = ScriptConstant(hashFunction(stackTop.bytes).bytes)
      ScriptProgram(program, hash :: program.stack.tail, program.script.tail)
    } else {
      logger.error("We must have the stack top defined to execute a hash function")
      ScriptProgram(program,ScriptErrorInvalidStackOperation)
    }
  }


  private def handleSignatureValidation(program: ScriptProgram, result: TransactionSignatureCheckerResult, restOfStack: Seq[ScriptToken]): ScriptProgram = result match {
    case SignatureValidationSuccess =>
      //means that all of the signatures were correctly encoded and
      //that all of the signatures were valid signatures for the given
      //public keys
      ScriptProgram(program, OP_TRUE +: restOfStack, program.script.tail)
    case SignatureValidationErrorNotStrictDerEncoding =>
      //this means the script fails immediately
      //set the valid flag to false on the script
      //see BIP66 for more information on this
      //https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki#specification
      ScriptProgram(program, ScriptErrorSigDer)
    case SignatureValidationErrorIncorrectSignatures =>
      //this means that signature verification failed, however all signatures were encoded correctly
      //just push a OP_FALSE onto the stack
      ScriptProgram(program, OP_FALSE +: restOfStack, program.script.tail)
    case SignatureValidationErrorSignatureCount =>
      //means that we did not have enough signatures for OP_CHECKMULTISIG
      ScriptProgram(program, ScriptErrorInvalidStackOperation)
    case SignatureValidationErrorPubKeyEncoding =>
      //means that a public key was not encoded correctly
      ScriptProgram(program, ScriptErrorPubKeyType)
    case SignatureValidationErrorHighSValue =>
      ScriptProgram(program, ScriptErrorSigHighS)
    case SignatureValidationErrorHashType =>
      ScriptProgram(program, ScriptErrorSigHashType)
    case SignatureValidationErrorWitnessPubKeyType =>
      ScriptProgram(program,ScriptErrorWitnessPubKeyType)
    case SignatureValidationErrorNullFail =>
      ScriptProgram(program,ScriptErrorSigNullFail)
  }

  /** Checks the given [[MerkleBlock]] to see if we have enough proof of work
    * [[https://github.com/ElementsProject/elements/blob/edaaa8b0f92653d9f770e671c7493f4bab4b48c7/src/pow.cpp#L40]]
    * */
  private def checkBitcoinProofOfWork(merkleBlock: MerkleBlock): Boolean = {
    true
  }

  /** Parses the withdraw script pubkey from the given contract
    * [[https://github.com/ElementsProject/elements/blob/6a3b75d257eeb9b4729e658821d3999430a5d5be/src/script/interpreter.cpp#L1567-L1573]]
    */
  private def parseWithdrawScriptPubKey(contract: Contract): ScriptPubKey = contract.prefix match {
    case P2PHContractPrefix =>
      val hash = contract.hash
      P2PKHScriptPubKey(hash)
    case P2SHContractPrefix =>
      val hash = contract.hash
      P2SHScriptPubKey(hash)
  }

}
