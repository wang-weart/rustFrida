use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_let_statement(&mut self) -> Result<DslStmt, String> {
        let stmts = self.parse_let_declarations_until(';')?;
        Ok(single_or_block(stmts))
    }

    pub(super) fn parse_let_declarations_until(&mut self, terminator: char) -> Result<Vec<DslStmt>, String> {
        let mut stmts = Vec::new();
        loop {
            stmts.push(self.parse_let_declaration()?);
            self.skip_ws();
            if self.peek() == Some(',') {
                self.expect_char(',')?;
                continue;
            }
            self.expect_char(terminator)?;
            break;
        }
        Ok(stmts)
    }

    fn parse_let_declaration(&mut self) -> Result<DslStmt, String> {
        self.skip_ws();
        let local_name = self.parse_ident()?;
        let local_name = self.declare_local(local_name)?;
        self.skip_ws();
        let type_name = if self.peek() == Some(':') {
            self.expect_char(':')?;
            Some(self.parse_type_name()?)
        } else {
            None
        };
        self.skip_ws();
        if self.peek() != Some('=') {
            let Some(type_name) = type_name else {
                return Err(self.err("uninitialized local declarations require an explicit type"));
            };
            return Ok(DslStmt::Let {
                name: local_name,
                type_name: Some(type_name.clone()),
                value: DslValue::DefaultValue { type_name },
            });
        }
        self.expect_char('=')?;
        self.skip_ws();
        if self.peek_ident("orig") {
            self.expect_ident("orig")?;
            let args = self.parse_orig_args()?;
            self.skip_ws();
            return Ok(DslStmt::LetOrig {
                name: local_name,
                type_name,
                args,
            });
        }
        let value = self.parse_value_arg()?;
        self.skip_ws();
        Ok(DslStmt::Let {
            name: local_name,
            type_name,
            value,
        })
    }

    pub(super) fn parse_orig_args(&mut self) -> Result<DslOrigArgs, String> {
        self.skip_ws();
        self.expect_char('(')?;
        self.skip_ws();
        if self.peek() == Some(')') {
            self.expect_char(')')?;
            return Ok(DslOrigArgs::Original);
        }
        let args = self.parse_value_arg_list_until_close()?;
        self.skip_ws();
        self.expect_char(')')?;
        Ok(DslOrigArgs::Values(args))
    }
}
