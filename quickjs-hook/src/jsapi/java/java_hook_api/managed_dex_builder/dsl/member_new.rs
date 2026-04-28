use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_js_new_member_value(&mut self, mut parts: Vec<String>) -> Result<DslValue, String> {
        if parts.len() < 2 || parts.pop().as_deref() != Some("$new") {
            return Err(self.err("expected Class.$new(...)"));
        }
        let class_name = parts.join(".");
        self.expect_char('(')?;
        let (ctor_sig, args) = self.parse_new_constructor_args()?;
        self.expect_char(')')?;
        Ok(DslValue::NewObject {
            class_name,
            ctor_sig,
            args,
        })
    }
}
