package org.bitcoins.core.protocol.script

import org.bitcoins.core.gen.ScriptGenerators
import org.scalacheck.{Prop, Properties}

/**
  * Created by chris on 3/15/17.
  */
class ContractSpec extends Properties("ContractSpec") {

  property("serialization symmetry") = {
    Prop.forAll(ScriptGenerators.contract) { contract =>
      Contract(contract.hex) == contract
    }
  }

  property("field access serialization symmetry") = {
    Prop.forAll(ScriptGenerators.contract) { contract =>
      val (prefix,nonce,hash) = (contract.prefix, contract.nonce, contract.hash)
      val c = Contract(prefix,nonce,hash)
      c.prefix == contract.prefix &&
      c.nonce == contract.nonce &&
      c.hash == contract.hash

    }
  }
}
