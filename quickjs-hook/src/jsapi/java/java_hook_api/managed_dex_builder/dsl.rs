use super::{build_method_sig, build_params_sig, java_class_to_descriptor_or_primitive, IfCmpOp};

mod assignment;
mod ast;
mod ast_call;
mod ast_condition;
mod ast_expr;
pub(super) use ast_condition::*;
mod ast_stmt;
pub(super) use ast_stmt::*;
mod ast_value;
mod condition;
mod control_flow;
mod control_loop;
mod control_switch;
mod control_try;
pub(super) use ast::*;
pub(super) use ast_call::*;
pub(super) use ast_expr::*;
mod cursor;
mod declaration;
mod expr_v2;
mod lexer;
use lexer::TokenKind as DslTokenKind;
mod operators;
mod parser;
use parser::{DslMark, DslParser};
mod scope;
mod statement_tail;
mod syntax;
mod token_stream;

mod expr_core;
mod helpers;
pub(super) use helpers::*;
mod statement;

pub(super) fn parse_managed_dsl(dsl: &str) -> Result<DslProgram, String> {
    let mut parser = DslParser::new(dsl)?;
    let stmts = parser.parse_statements(false)?;
    parser.skip_ws();
    parser.expect_eof()?;
    Ok(DslProgram { stmts })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expression_v2_parses_direct_receiver_call_as_primary_path() {
        let program = parse_managed_dsl("return this.size();").unwrap();
        let [DslStmt::ReturnValue {
            value: Some(DslValue::Call(call)),
        }] = program.stmts.as_slice()
        else {
            panic!("expected return call");
        };
        assert_eq!(call.method_name, "size");
        assert_eq!(call.sig, "");
        assert!(matches!(call.target.as_ref(), Some(DslTarget::This)));
        assert!(call.receiver.is_none());
        assert!(call.args.is_empty());
    }

    #[test]
    fn expression_v2_parses_expression_statement_receiver_call() {
        let program = parse_managed_dsl("this.clear();").unwrap();
        let [DslStmt::Call(call)] = program.stmts.as_slice() else {
            panic!("expected call statement");
        };
        assert_eq!(call.method_name, "clear");
        assert_eq!(call.sig, "");
        assert!(matches!(call.target.as_ref(), Some(DslTarget::This)));
        assert!(call.receiver.is_none());
        assert!(call.args.is_empty());
    }

    #[test]
    fn expression_v2_parses_for_update_receiver_call() {
        let program = parse_managed_dsl("for (; true; this.clear()) { break; }").unwrap();
        let [DslStmt::For { update_stmts, .. }] = program.stmts.as_slice() else {
            panic!("expected for statement");
        };
        let [DslStmt::Call(call)] = update_stmts.as_slice() else {
            panic!("expected call update");
        };
        assert_eq!(call.method_name, "clear");
        assert!(matches!(call.target.as_ref(), Some(DslTarget::This)));
    }

    #[test]
    fn expression_v2_parses_chained_member_call_without_fallback() {
        let program = parse_managed_dsl("return this.entrySet().iterator().hasNext();").unwrap();
        let [DslStmt::ReturnValue {
            value: Some(DslValue::Call(call)),
        }] = program.stmts.as_slice()
        else {
            panic!("expected return call");
        };
        assert_eq!(call.method_name, "hasNext");
        assert!(call.receiver.is_some());
    }

    #[test]
    fn expression_v2_parses_parenthesized_ternary_condition() {
        let program = parse_managed_dsl(
            "let has: boolean = this.containsKey(arg0); if (((this.size() >= 0 && has) ? true : false)) { return orig(arg0, arg1); } return orig(arg0, arg1);",
        )
        .unwrap();
        assert_eq!(program.stmts.len(), 3);
    }

    #[test]
    fn expression_v2_parses_comprehensive_expression_and_type_surface() {
        let program = parse_managed_dsl(
            "count(\"hit\");\
             let n: int = this.size();\
             let calc: int = (((n + 3) * 2) - 1) ^ ((n << 1) | (n >>> 1));\
             calc += (~n & 7);\
             let neg: int = -calc;\
             let maxv: int = java.lang.Integer.MAX_VALUE(\"int\");\
             let ok: boolean = this.containsKey(arg0);\
             let keys: java.util.Set = this.keySet();\
             let it: java.util.Iterator = keys.iterator();\
             let selected: java.lang.Object = ok ? arg0 : arg1;\
             let sb: java.lang.StringBuilder = new java.lang.StringBuilder(\"java.lang.String\", \"rf\");\
             sb.append(selected);\
             let text: java.lang.String = java.lang.String.valueOf(selected);\
             let asObj: java.lang.Object = text as java.lang.Object;\
             let objs: java.lang.Object[] = [selected, asObj, null];\
             let obj0: java.lang.Object = objs[0];\
             let arr: int[] = new int[](n + 3);\
             arr[0] = calc;\
             arr[0] += n;\
             arr[0]++;\
             for (let i: int = 0; i < 2; i++) { arr[0] += i; }\
             if ((((ok && it.hasNext()) ? true : false) || arr.length > 0)) { java.lang.String.valueOf(obj0); }\
             return orig(arg0, arg1);",
        )
        .unwrap();

        assert!(matches!(program.stmts.first(), Some(DslStmt::Count { name }) if name == "hit"));
        assert!(program.stmts.iter().any(|stmt| matches!(
            stmt,
            DslStmt::Let {
                type_name: Some(type_name),
                value: DslValue::FieldGet { is_static: true, .. },
                ..
            } if type_name == "int"
        )));
        assert!(program.stmts.iter().any(|stmt| matches!(
            stmt,
            DslStmt::Let {
                type_name: Some(type_name),
                value: DslValue::ArrayLiteral { .. },
                ..
            } if type_name == "java.lang.Object[]"
        )));
        assert!(program.stmts.iter().any(|stmt| matches!(
            stmt,
            DslStmt::Let {
                type_name: Some(type_name),
                value: DslValue::NewArray { .. },
                ..
            } if type_name == "int[]"
        )));
        assert!(program.stmts.iter().any(|stmt| matches!(stmt, DslStmt::For { .. })));
        assert!(matches!(
            program.stmts.last(),
            Some(DslStmt::ReturnOrig {
                args: DslOrigArgs::Values(args)
            }) if args.len() == 2
        ));
    }

    #[test]
    fn expression_v2_preserves_direct_call_inference_shape() {
        let program = parse_managed_dsl(
            "let has: boolean = this.containsKey(arg0);\
             let text: java.lang.String = java.lang.String.valueOf(arg1);\
             return text;",
        )
        .unwrap();

        let [DslStmt::Let {
            value: DslValue::Call(receiver_call),
            ..
        }, DslStmt::Let {
            value: DslValue::Call(static_call),
            ..
        }, _] = program.stmts.as_slice()
        else {
            panic!("expected receiver and static direct calls");
        };
        assert_eq!(receiver_call.method_name, "containsKey");
        assert_eq!(receiver_call.sig, "");
        assert!(matches!(receiver_call.target.as_ref(), Some(DslTarget::This)));
        assert_eq!(static_call.class_name.as_deref(), Some("java.lang.String"));
        assert_eq!(static_call.method_name, "valueOf");
        assert_eq!(static_call.sig, "");
    }

    #[test]
    fn expression_v2_preserves_explicit_overload_disambiguation() {
        let program = parse_managed_dsl("return this.get.overload(\"java.lang.Object\")(arg0);").unwrap();
        let [DslStmt::ReturnValue {
            value: Some(DslValue::Call(call)),
        }] = program.stmts.as_slice()
        else {
            panic!("expected overload call");
        };
        assert_eq!(call.method_name, "get");
        assert_eq!(call.sig, "(Ljava/lang/Object;)");
    }

    #[test]
    fn expression_v2_parses_new_statement_through_expression_path() {
        let program = parse_managed_dsl("new int[](3); let a: int[] = new int[](this.size());").unwrap();
        assert_eq!(program.stmts.len(), 2);
        assert!(matches!(program.stmts[0], DslStmt::NewArray { .. }));
        assert!(matches!(
            &program.stmts[1],
            DslStmt::Let {
                value: DslValue::NewArray { .. },
                ..
            }
        ));
    }

    #[test]
    fn expression_v2_reports_inner_syntax_error_without_fallback() {
        let err = match parse_managed_dsl("return this.size(;") {
            Ok(_) => panic!("expected parse error"),
            Err(err) => err,
        };
        assert!(err.contains("expected expression"), "{err}");
    }

    #[test]
    fn expression_v2_reports_trailing_tail_without_fallback() {
        let err = match parse_managed_dsl("return this.size()();") {
            Ok(_) => panic!("expected parse error"),
            Err(err) => err,
        };
        assert!(err.contains("unsupported expression tail"), "{err}");
    }
}
