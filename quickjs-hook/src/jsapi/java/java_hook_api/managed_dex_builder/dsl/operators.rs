use super::*;

const COMPOUND_ASSIGN_OPS: &[(&str, DslIntBinOp)] = &[
    (">>>=", DslIntBinOp::Ushr),
    ("<<=", DslIntBinOp::Shl),
    (">>=", DslIntBinOp::Shr),
    ("+=", DslIntBinOp::Add),
    ("-=", DslIntBinOp::Sub),
    ("*=", DslIntBinOp::Mul),
    ("/=", DslIntBinOp::Div),
    ("%=", DslIntBinOp::Rem),
    ("&=", DslIntBinOp::And),
    ("|=", DslIntBinOp::Or),
    ("^=", DslIntBinOp::Xor),
];

impl<'a> DslParser<'a> {
    pub(super) fn peek_compound_assign_op(&self) -> Option<DslIntBinOp> {
        COMPOUND_ASSIGN_OPS
            .iter()
            .find_map(|(token, op)| self.peek_op(token).then_some(*op))
    }

    pub(super) fn consume_compound_assign_op(&mut self, op: DslIntBinOp) -> Result<(), String> {
        let Some((token, _)) = COMPOUND_ASSIGN_OPS.iter().find(|(_, candidate)| *candidate == op) else {
            return Err(self.err("unsupported compound assignment operator"));
        };
        self.expect_op(token)
    }
}
