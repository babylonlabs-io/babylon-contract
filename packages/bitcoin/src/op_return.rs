use bitcoin::blockdata::opcodes;
use bitcoin::Transaction;

pub fn extract_op_return_data(tx: &Transaction) -> Result<Vec<u8>, String> {
    for output in tx.output.iter() {
        if output.script_pubkey.is_op_return() {
            let pk_script = output.script_pubkey.as_bytes();

            // if this is OP_PUSHDATA1, we need to drop first 3 bytes as those are related
            // to script iteslf i.e OP_RETURN + OP_PUSHDATA1 + len of bytes
            if pk_script[1] == opcodes::all::OP_PUSHDATA1.to_u8() {
                return Ok(pk_script[3..pk_script.len()].to_vec());
            } else {
                return Ok(pk_script[2..pk_script.len()].to_vec());
            }
        }
    }
    Err("no op_return data in this BTC tx".to_string())
}
