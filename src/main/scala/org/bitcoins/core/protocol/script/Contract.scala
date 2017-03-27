package org.bitcoins.core.protocol.script

import java.security.SecureRandom
import java.util.Random

import org.bitcoins.core.crypto.Sha256Hash160Digest
import org.bitcoins.core.protocol.NetworkElement
import org.bitcoins.core.util.{BitcoinSUtil, Factory}

/**
  * Created by chris on 3/15/17.
  */

/** Pays to contract hash
  * This data structure represents a contract inside of a [[WithdrawScriptSignature]]
  * */
sealed trait Contract extends NetworkElement {
  /** Prefix is either [[P2SHContractPrefix]] or [[P2PHContractPrefix]] */
  def prefix: ContractPrefix = ContractPrefix(bytes.take(4))

  /** 16 Bytes of randomness */
  def nonce: Seq[Byte] = bytes.slice(4,20)

  /** The hash we are paying to */
  def hash: Sha256Hash160Digest = Sha256Hash160Digest(bytes.takeRight(20))

  override def hex = BitcoinSUtil.encodeHex(bytes)

  def bytes: Seq[Byte]

  override def toString = "Contract(" + hex + ")"
}

object Contract extends Factory[Contract] {
  private case class ContractImpl(override val bytes: Seq[Byte]) extends Contract {
    require(bytes.length == 40, "Contract must be 40 bytes in size")
  }

  def apply(prefix: ContractPrefix, nonce: Seq[Byte], hash: Sha256Hash160Digest): Contract = {
    require(nonce.length == 16, "Nonce must be 16 bytes to create a contract")
    val bytes: Seq[Byte] = prefix.bytes ++ nonce ++ hash.bytes
    Contract(bytes)
  }

  def apply(prefix: ContractPrefix, hash: Sha256Hash160Digest): Contract = {
    val nonce = new Array[Byte](16)
    scala.util.Random.nextBytes(nonce)
    Contract(prefix,nonce,hash)
  }

  override def fromBytes(bytes: Seq[Byte]): Contract = ContractImpl(bytes)
}

sealed trait ContractPrefix extends NetworkElement {
  val prefix: Seq[Byte]
  override def bytes: Seq[Byte] = prefix
  override def hex = BitcoinSUtil.encodeHex(bytes)
}

object ContractPrefix {
  def apply(bytes: Seq[Byte]): ContractPrefix = {
    require(bytes.length == 4, "Contract prefix must be 4 bytes in size")
    val p = prefixes.find(_.prefix == bytes)
    require(p.isDefined)
    p.get
  }


  def prefixes = Seq(P2PHContractPrefix,P2SHContractPrefix)
}

case object P2SHContractPrefix extends ContractPrefix {
  val prefix = Seq('P','2','S','H').map(_.toByte)
}
case object P2PHContractPrefix extends ContractPrefix {
  val prefix = Seq('P', '2','P','H').map(_.toByte)
}
