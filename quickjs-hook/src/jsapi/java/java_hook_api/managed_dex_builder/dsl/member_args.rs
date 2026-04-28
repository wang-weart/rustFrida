use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_member_call_args(
        &mut self,
        allow_field: bool,
        allow_explicit_class: bool,
    ) -> Result<ParsedCallArgs, String> {
        self.skip_ws();
        if self.peek() == Some(')') {
            self.expect_char(')')?;
            return Ok(ParsedCallArgs::Direct(Vec::new()));
        }

        if self.peek_string() {
            let first = self.parse_string_arg()?;
            self.skip_ws();
            if first.starts_with('(') {
                let args = self.parse_optional_value_args()?;
                self.expect_char(')')?;
                return Ok(ParsedCallArgs::LegacyCall {
                    class_name: None,
                    sig: first,
                    args,
                });
            }
            if allow_explicit_class && self.peek() == Some(',') && looks_like_type_name(&first) {
                let checkpoint = self.mark();
                self.expect_char(',')?;
                self.skip_ws();
                if self.peek_string() {
                    let second = self.parse_string_arg()?;
                    if second.starts_with('(') {
                        let args = self.parse_optional_value_args()?;
                        self.expect_char(')')?;
                        return Ok(ParsedCallArgs::LegacyCall {
                            class_name: Some(first),
                            sig: second,
                            args,
                        });
                    }
                }
                self.restore(checkpoint);
            }
            if allow_field && self.peek() == Some(')') && looks_like_type_name(&first) {
                self.expect_char(')')?;
                return Ok(ParsedCallArgs::Field {
                    class_name: None,
                    type_name: first,
                });
            }

            let mut args = vec![DslValue::String(first)];
            while self.peek() == Some(',') {
                self.expect_char(',')?;
                args.push(self.parse_value_arg()?);
                self.skip_ws();
            }
            self.expect_char(')')?;
            return Ok(ParsedCallArgs::Direct(args));
        }

        let args = self.parse_value_arg_list_until_close()?;
        self.expect_char(')')?;
        Ok(ParsedCallArgs::Direct(args))
    }
}
