use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_value_arg(&mut self) -> Result<DslValue, String> {
        self.parse_ternary_expr()
    }

    pub(super) fn parse_non_ternary_value_arg(&mut self) -> Result<DslValue, String> {
        self.parse_expr_v2()
    }

    pub(super) fn parse_value_arg_list_until_close(&mut self) -> Result<Vec<DslValue>, String> {
        let mut args = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(')') {
                break;
            }
            args.push(self.parse_value_arg()?);
            self.skip_ws();
            if self.peek() != Some(',') {
                break;
            }
            self.expect_char(',')?;
        }
        Ok(args)
    }

    fn parse_ternary_expr(&mut self) -> Result<DslValue, String> {
        let checkpoint = self.mark();
        if let Ok(condition) = self.parse_condition() {
            self.skip_ws();
            if self.peek() == Some('?') {
                self.expect_char('?')?;
                let then_value = self.parse_value_arg()?;
                self.expect_char(':')?;
                let else_value = self.parse_value_arg()?;
                return Ok(fold_ternary(condition, then_value, else_value));
            }
        }
        self.restore(checkpoint);
        self.parse_expr_v2()
    }
}
