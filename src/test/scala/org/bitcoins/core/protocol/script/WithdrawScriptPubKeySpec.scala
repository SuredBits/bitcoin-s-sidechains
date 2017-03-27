package org.bitcoins.core.protocol.script

import org.bitcoins.core.gen.{CryptoGenerators, ScriptGenerators}
import org.scalacheck.{Prop, Properties}

/**
  * Created by chris on 3/13/17.
  */
class WithdrawScriptPubKeySpec extends Properties("WithdrawScriptPubKeySpec") {

  property("get genesis hash for the blockchain we are pegged to") =
    Prop.forAll(CryptoGenerators.doubleSha256Digest) { hash =>
      val w = WithdrawScriptPubKey(hash)
      w.genesisHash == hash
    }

  property("serialization symmetry") =
    Prop.forAll(ScriptGenerators.withdrawScriptPubKey) { case (withdrawScriptPubKey,_) =>
      WithdrawScriptPubKey(withdrawScriptPubKey.hex) == withdrawScriptPubKey
    }
}
