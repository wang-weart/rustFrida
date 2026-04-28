use std::collections::BTreeMap;

use super::{build_method_sig, build_params_sig, java_class_to_descriptor_or_primitive, IfCmpOp};

mod lexer;
use lexer::{lex as dsl_lex, Token as DslToken, TokenKind as DslTokenKind};

mod expression;
mod statement;

pub(super) struct DslProgram {
    pub(super) stmts: Vec<DslStmt>,
}

#[derive(Clone)]
pub(super) enum DslStmt {
    Block(Vec<DslStmt>),
    Let {
        name: String,
        type_name: Option<String>,
        value: DslValue,
    },
    Assign {
        name: String,
        value: DslValue,
    },
    LetOrig {
        name: String,
        type_name: Option<String>,
        args: DslOrigArgs,
    },
    New {
        class_name: String,
        ctor_sig: Option<String>,
        args: Vec<DslValue>,
    },
    NewArray {
        array_type_name: String,
        size: DslValue,
    },
    Call(DslCallStmt),
    Cast {
        value: DslValue,
        class_name: String,
    },
    ArrayLength {
        array: DslValue,
    },
    ArrayGet {
        array: DslValue,
        index: DslValue,
        type_name: Option<String>,
    },
    ArrayPut {
        array: DslValue,
        index: DslValue,
        type_name: Option<String>,
        value: DslValue,
    },
    ArrayUpdate {
        array: DslValue,
        index: DslValue,
        type_name: Option<String>,
        op: DslIntBinOp,
        value: DslValue,
    },
    FieldRead {
        stmt: DslFieldStmt,
        is_static: bool,
    },
    FieldWrite {
        stmt: DslFieldStmt,
        is_static: bool,
    },
    FieldUpdate {
        stmt: DslFieldStmt,
        is_static: bool,
        op: DslIntBinOp,
        value: DslValue,
    },
    IfNull {
        value: DslValue,
        invert: bool,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfBool {
        value: DslValue,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfCmp {
        op: IfCmpOp,
        left: DslValue,
        right: DslValue,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfInstanceOf {
        value: DslValue,
        class_name: String,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    Switch {
        value: DslValue,
        cases: Vec<(i16, Vec<DslStmt>)>,
        default_stmts: Option<Vec<DslStmt>>,
    },
    TryCatch {
        try_stmts: Vec<DslStmt>,
        catches: Vec<DslCatch>,
    },
    While {
        condition: DslCondition,
        body_stmts: Vec<DslStmt>,
    },
    DoWhile {
        body_stmts: Vec<DslStmt>,
        condition: DslCondition,
    },
    For {
        init_stmts: Vec<DslStmt>,
        condition: Option<DslCondition>,
        update_stmts: Vec<DslStmt>,
        body_stmts: Vec<DslStmt>,
    },
    Break,
    Continue,
    Count {
        name: String,
    },
    Throw {
        value: DslValue,
    },
    ReturnOrig {
        args: DslOrigArgs,
    },
    ReturnValue {
        value: Option<DslValue>,
    },
}

#[derive(Clone)]
pub(super) struct DslCatch {
    pub(super) catch_type: String,
    pub(super) catch_name: String,
    pub(super) catch_stmts: Vec<DslStmt>,
}

#[derive(Clone)]
pub(super) enum DslOrigArgs {
    Original,
    Values(Vec<DslValue>),
}

#[derive(Clone)]
pub(super) struct DslCallStmt {
    pub(super) kind: DslCallKind,
    pub(super) target: Option<DslTarget>,
    pub(super) receiver: Option<Box<DslValue>>,
    pub(super) null_safe: bool,
    pub(super) class_name: Option<String>,
    pub(super) method_name: String,
    pub(super) sig: String,
    pub(super) args: Vec<DslValue>,
}

impl DslCallStmt {
    pub(super) fn class_label(&self) -> &str {
        self.class_name.as_deref().unwrap_or("<inferred>")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DslCallKind {
    Virtual,
    Interface,
    Static,
}

enum ParsedCallArgs {
    Direct(Vec<DslValue>),
    LegacyCall {
        class_name: Option<String>,
        sig: String,
        args: Vec<DslValue>,
    },
    Field {
        class_name: Option<String>,
        type_name: String,
    },
}

#[derive(Clone)]
pub(super) struct DslFieldStmt {
    pub(super) target: Option<DslTarget>,
    pub(super) receiver: Option<Box<DslValue>>,
    pub(super) class_name: Option<String>,
    pub(super) field_name: String,
    pub(super) type_name: String,
    pub(super) value: Option<DslValue>,
}

#[derive(Clone)]
pub(super) enum DslValue {
    Target(DslTarget),
    String(String),
    Int(i16),
    Bool(bool),
    Null,
    UnaryOp {
        op: DslUnaryOp,
        value: Box<DslValue>,
    },
    IntBinOp {
        op: DslIntBinOp,
        left: Box<DslValue>,
        right: Box<DslValue>,
    },
    Ternary {
        condition: Box<DslCondition>,
        then_value: Box<DslValue>,
        else_value: Box<DslValue>,
    },
    OrigCall(DslOrigArgs),
    Call(DslCallStmt),
    NewObject {
        class_name: String,
        ctor_sig: Option<String>,
        args: Vec<DslValue>,
    },
    FieldGet {
        stmt: Box<DslFieldStmt>,
        is_static: bool,
    },
    Cast {
        value: Box<DslValue>,
        class_name: String,
    },
    ArrayLength(Box<DslValue>),
    ArrayLiteral {
        elements: Vec<DslValue>,
    },
    ArrayGet {
        array: Box<DslValue>,
        index: Box<DslValue>,
        type_name: Option<String>,
    },
}

#[derive(Clone, Copy)]
pub(super) enum DslUnaryOp {
    Neg,
    BitNot,
    BoolNot,
}

#[derive(Clone, Copy)]
pub(super) enum DslIntBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Ushr,
}

#[derive(Clone)]
pub(super) enum DslCondition {
    Null {
        value: DslValue,
        invert: bool,
    },
    Cmp {
        op: IfCmpOp,
        left: DslValue,
        right: DslValue,
    },
    InstanceOf {
        value: DslValue,
        class_name: String,
    },
    Bool {
        value: DslValue,
    },
    Const(bool),
    And(Box<DslCondition>, Box<DslCondition>),
    Or(Box<DslCondition>, Box<DslCondition>),
    Not(Box<DslCondition>),
}

impl DslCondition {
    fn into_if_stmt(self, then_stmts: Vec<DslStmt>, else_stmts: Vec<DslStmt>) -> DslStmt {
        match self {
            DslCondition::Const(true) => DslStmt::Block(then_stmts),
            DslCondition::Const(false) => DslStmt::Block(else_stmts),
            DslCondition::Null { value, invert } => DslStmt::IfNull {
                value,
                invert,
                then_stmts,
                else_stmts,
            },
            DslCondition::Bool { value } => DslStmt::IfBool {
                value,
                then_stmts,
                else_stmts,
            },
            DslCondition::Cmp { op, left, right } => DslStmt::IfCmp {
                op,
                left,
                right,
                then_stmts,
                else_stmts,
            },
            DslCondition::InstanceOf { value, class_name } => DslStmt::IfInstanceOf {
                value,
                class_name,
                then_stmts,
                else_stmts,
            },
            DslCondition::And(left, right) => {
                let inner = right.into_if_stmt(then_stmts, else_stmts.clone());
                left.into_if_stmt(vec![inner], else_stmts)
            }
            DslCondition::Or(left, right) => {
                let inner = right.into_if_stmt(then_stmts.clone(), else_stmts);
                left.into_if_stmt(then_stmts, vec![inner])
            }
            DslCondition::Not(condition) => condition.into_if_stmt(else_stmts, then_stmts),
        }
    }
}

fn condition_and(left: DslCondition, right: DslCondition) -> DslCondition {
    match (left, right) {
        (DslCondition::Const(false), _) | (_, DslCondition::Const(false)) => DslCondition::Const(false),
        (DslCondition::Const(true), right) => right,
        (left, DslCondition::Const(true)) => left,
        (left, right) => DslCondition::And(Box::new(left), Box::new(right)),
    }
}

fn condition_or(left: DslCondition, right: DslCondition) -> DslCondition {
    match (left, right) {
        (DslCondition::Const(true), _) | (_, DslCondition::Const(true)) => DslCondition::Const(true),
        (DslCondition::Const(false), right) => right,
        (left, DslCondition::Const(false)) => left,
        (left, right) => DslCondition::Or(Box::new(left), Box::new(right)),
    }
}

fn condition_not(condition: DslCondition) -> DslCondition {
    match condition {
        DslCondition::Const(value) => DslCondition::Const(!value),
        DslCondition::Not(inner) => *inner,
        other => DslCondition::Not(Box::new(other)),
    }
}

fn fold_ternary(condition: DslCondition, then_value: DslValue, else_value: DslValue) -> DslValue {
    match condition {
        DslCondition::Const(true) => then_value,
        DslCondition::Const(false) => else_value,
        condition => DslValue::Ternary {
            condition: Box::new(condition),
            then_value: Box::new(then_value),
            else_value: Box::new(else_value),
        },
    }
}

fn single_or_block(mut stmts: Vec<DslStmt>) -> DslStmt {
    if stmts.len() == 1 {
        stmts.remove(0)
    } else {
        DslStmt::Block(stmts)
    }
}

impl DslValue {
    fn into_bool_condition(self) -> DslCondition {
        match self {
            DslValue::Bool(value) => DslCondition::Const(value),
            value => DslCondition::Bool { value },
        }
    }

    fn into_statement(self) -> Option<DslStmt> {
        match self {
            DslValue::Call(stmt) => Some(DslStmt::Call(stmt)),
            DslValue::NewObject {
                class_name,
                ctor_sig,
                args,
            } => Some(DslStmt::New {
                class_name,
                ctor_sig,
                args,
            }),
            DslValue::FieldGet { stmt, is_static } => Some(DslStmt::FieldRead { stmt: *stmt, is_static }),
            DslValue::Cast { value, class_name } => Some(DslStmt::Cast {
                value: *value,
                class_name,
            }),
            DslValue::ArrayLength(array) => Some(DslStmt::ArrayLength { array: *array }),
            DslValue::ArrayGet {
                array,
                index,
                type_name,
            } => Some(DslStmt::ArrayGet {
                array: *array,
                index: *index,
                type_name,
            }),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub(super) enum DslTarget {
    This,
    Arg(usize),
    Last,
    Result,
    Local(String),
}

pub(super) fn parse_managed_dsl(dsl: &str) -> Result<DslProgram, String> {
    let mut parser = DslParser::new(dsl)?;
    let stmts = parser.parse_statements(false)?;
    parser.skip_ws();
    parser.expect_eof()?;
    Ok(DslProgram { stmts })
}

struct DslParser<'a> {
    input: &'a str,
    tokens: Vec<DslToken>,
    pos: usize,
    local_scopes: Vec<BTreeMap<String, String>>,
    next_local_id: usize,
}

impl<'a> DslParser<'a> {
    fn new(input: &'a str) -> Result<Self, String> {
        Ok(Self {
            input,
            tokens: dsl_lex(input)?,
            pos: 0,
            local_scopes: vec![BTreeMap::new()],
            next_local_id: 0,
        })
    }

    fn with_local_scope<F, R>(&mut self, f: F) -> Result<R, String>
    where
        F: FnOnce(&mut Self) -> Result<R, String>,
    {
        self.local_scopes.push(BTreeMap::new());
        let result = f(self);
        self.local_scopes.pop();
        result
    }

    fn declare_local(&mut self, source_name: String) -> Result<String, String> {
        let Some(scope) = self.local_scopes.last_mut() else {
            return Err(self.err("internal parser scope error"));
        };
        if scope.contains_key(&source_name) {
            return Err(self.err(&format!("local '{}' is already declared in this scope", source_name)));
        }
        let internal_name = format!("__rf_l{}_{}", self.next_local_id, source_name);
        self.next_local_id += 1;
        scope.insert(source_name, internal_name.clone());
        Ok(internal_name)
    }

    fn resolve_local(&self, source_name: &str) -> Option<String> {
        self.local_scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(source_name).cloned())
    }

    fn resolve_local_name_or_source(&self, source_name: String) -> String {
        self.resolve_local(&source_name).unwrap_or(source_name)
    }

    fn scoped_target_name(&self, name: &str) -> Option<DslTarget> {
        match parse_target_name(name) {
            Some(DslTarget::Local(local)) => Some(DslTarget::Local(self.resolve_local(&local).unwrap_or(local))),
            other => other,
        }
    }

    fn skip_ws(&mut self) {}

    fn expect_ident(&mut self, expected: &str) -> Result<(), String> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Ident(value)) if value == expected => {
                self.pos += 1;
                Ok(())
            }
            _ => Err(self.err(&format!("expected identifier {}", expected))),
        }
    }

    fn peek_ident(&self, expected: &str) -> bool {
        matches!(self.tokens.get(self.pos).map(|token| &token.kind), Some(DslTokenKind::Ident(value)) if value == expected)
    }

    fn parse_ident(&mut self) -> Result<String, String> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Ident(value)) => {
                self.pos += 1;
                Ok(value.clone())
            }
            _ => Err(self.err("expected identifier")),
        }
    }

    fn expect_char(&mut self, expected: char) -> Result<(), String> {
        match self.peek() {
            Some(ch) if ch == expected => {
                self.pos += 1;
                Ok(())
            }
            _ => Err(self.err(&format!("expected '{}'", expected))),
        }
    }

    fn parse_string_arg(&mut self) -> Result<String, String> {
        self.skip_ws();
        let value = self.parse_string()?;
        self.skip_ws();
        Ok(value)
    }

    fn parse_string(&mut self) -> Result<String, String> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::String(value)) => {
                self.pos += 1;
                Ok(value.clone())
            }
            _ => Err(self.err("expected string")),
        }
    }

    fn parse_type_name(&mut self) -> Result<String, String> {
        self.skip_ws();
        if self.peek_string() {
            return self.parse_string_arg();
        }
        let mut name = self.parse_ident()?;
        loop {
            self.skip_ws();
            match self.peek() {
                Some('.') => {
                    self.expect_char('.')?;
                    let part = self.parse_ident()?;
                    name.push('.');
                    name.push_str(&part);
                }
                Some('[') => {
                    self.expect_char('[')?;
                    self.expect_char(']')?;
                    name.push_str("[]");
                }
                _ => break,
            }
        }
        self.skip_ws();
        Ok(name)
    }

    fn parse_i16(&mut self) -> Result<i16, String> {
        self.skip_ws();
        let negative = if self.peek() == Some('-') {
            self.pos += 1;
            true
        } else {
            false
        };
        let value_text = match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Number(value)) => {
                self.pos += 1;
                value.clone()
            }
            _ => return Err(self.err("expected integer")),
        };
        let value: i32 = value_text.parse().map_err(|_| self.err("invalid integer"))?;
        let signed = if negative { -value } else { value };
        if signed < i16::MIN as i32 || signed > i16::MAX as i32 {
            return Err(self.err("integer must fit int16"));
        }
        self.skip_ws();
        Ok(signed as i16)
    }

    fn peek_compound_assign_op(&self) -> Option<DslIntBinOp> {
        if self.peek_op(">>>=") {
            return Some(DslIntBinOp::Ushr);
        }
        if self.peek_op("<<=") {
            return Some(DslIntBinOp::Shl);
        }
        if self.peek_op(">>=") {
            return Some(DslIntBinOp::Shr);
        }
        if self.peek_op("+=") {
            return Some(DslIntBinOp::Add);
        }
        if self.peek_op("-=") {
            return Some(DslIntBinOp::Sub);
        }
        if self.peek_op("*=") {
            return Some(DslIntBinOp::Mul);
        }
        if self.peek_op("/=") {
            return Some(DslIntBinOp::Div);
        }
        if self.peek_op("%=") {
            return Some(DslIntBinOp::Rem);
        }
        if self.peek_op("&=") {
            return Some(DslIntBinOp::And);
        }
        if self.peek_op("|=") {
            return Some(DslIntBinOp::Or);
        }
        if self.peek_op("^=") {
            return Some(DslIntBinOp::Xor);
        }
        None
    }

    fn consume_compound_assign_op(&mut self, op: DslIntBinOp) -> Result<(), String> {
        match op {
            DslIntBinOp::Ushr => self.expect_op(">>>="),
            DslIntBinOp::Shl => self.expect_op("<<="),
            DslIntBinOp::Shr => self.expect_op(">>="),
            DslIntBinOp::Add => self.expect_op("+="),
            DslIntBinOp::Sub => self.expect_op("-="),
            DslIntBinOp::Mul => self.expect_op("*="),
            DslIntBinOp::Div => self.expect_op("/="),
            DslIntBinOp::Rem => self.expect_op("%="),
            DslIntBinOp::And => self.expect_op("&="),
            DslIntBinOp::Or => self.expect_op("|="),
            DslIntBinOp::Xor => self.expect_op("^="),
        }
    }

    fn local_increment_stmt(&self, name: String, delta: i16) -> DslStmt {
        let op = if delta >= 0 { DslIntBinOp::Add } else { DslIntBinOp::Sub };
        self.local_compound_assign_stmt(name, op, DslValue::Int(delta.abs()))
    }

    fn local_compound_assign_stmt(&self, name: String, op: DslIntBinOp, rhs: DslValue) -> DslStmt {
        let left = DslValue::Target(DslTarget::Local(name.clone()));
        DslStmt::Assign {
            name,
            value: fold_int_binop(op, left, rhs),
        }
    }

    fn increment_value_stmt(&self, value: DslValue, delta: i16) -> Result<DslStmt, String> {
        let op = if delta >= 0 { DslIntBinOp::Add } else { DslIntBinOp::Sub };
        self.compound_assign_value_stmt(value, op, DslValue::Int(delta.abs()))
    }

    fn compound_assign_value_stmt(&self, value: DslValue, op: DslIntBinOp, rhs: DslValue) -> Result<DslStmt, String> {
        match value {
            DslValue::FieldGet { stmt, is_static } => Ok(DslStmt::FieldUpdate {
                stmt: *stmt,
                is_static,
                op,
                value: rhs,
            }),
            DslValue::ArrayGet {
                array,
                index,
                type_name,
            } => Ok(DslStmt::ArrayUpdate {
                array: *array,
                index: *index,
                type_name,
                op,
                value: rhs,
            }),
            DslValue::Target(DslTarget::Local(name)) => Ok(self.local_compound_assign_stmt(name, op, rhs)),
            _ => Err(self.err("compound assignment supports locals, fields, and array elements")),
        }
    }

    fn expect_eof(&self) -> Result<(), String> {
        if self.pos == self.tokens.len() {
            Ok(())
        } else {
            Err(self.err("unexpected trailing input"))
        }
    }

    fn peek(&self) -> Option<char> {
        match self.tokens.get(self.pos).map(|token| &token.kind) {
            Some(DslTokenKind::Symbol(ch)) => Some(*ch),
            _ => None,
        }
    }

    fn peek_string(&self) -> bool {
        matches!(
            self.tokens.get(self.pos).map(|token| &token.kind),
            Some(DslTokenKind::String(_))
        )
    }

    fn peek_number(&self) -> bool {
        matches!(
            self.tokens.get(self.pos).map(|token| &token.kind),
            Some(DslTokenKind::Number(_))
        )
    }

    fn peek_op(&self, expected: &str) -> bool {
        matches!(self.tokens.get(self.pos).map(|token| &token.kind), Some(DslTokenKind::Op(value)) if *value == expected)
    }

    fn expect_op(&mut self, expected: &str) -> Result<(), String> {
        if self.peek_op(expected) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(&format!("expected operator {}", expected)))
        }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.tokens.len()
    }

    fn err(&self, msg: &str) -> String {
        let byte = self
            .tokens
            .get(self.pos)
            .map(|token| token.byte)
            .unwrap_or_else(|| self.input.len());
        format!("managed dex DSL parse error at byte {}: {}", byte, msg)
    }
}

fn parse_target_name(name: &str) -> Option<DslTarget> {
    match name {
        "this" | "$this" => Some(DslTarget::This),
        "last" | "$last" => Some(DslTarget::Last),
        "result" | "$result" => Some(DslTarget::Result),
        value if value.starts_with("arg") => value[3..].parse::<usize>().ok().map(DslTarget::Arg),
        value if value.starts_with('$') => value[1..].parse::<usize>().ok().map(DslTarget::Arg),
        value if value.starts_with('p') => value[1..].parse::<usize>().ok().map(DslTarget::Arg),
        value if is_local_ident(value) => Some(DslTarget::Local(value.to_string())),
        _ => None,
    }
}

fn looks_like_type_name(value: &str) -> bool {
    matches!(
        value,
        "boolean" | "byte" | "char" | "short" | "int" | "long" | "float" | "double" | "void"
    ) || matches!(value, "Z" | "B" | "C" | "S" | "I" | "J" | "F" | "D" | "V")
        || value.starts_with('[')
        || (value.starts_with('L') && value.ends_with(';'))
        || value.ends_with("[]")
        || value.contains('.')
        || value.contains('/')
}

fn looks_like_static_class_name(value: &str) -> bool {
    value.chars().next().map(|ch| ch.is_ascii_uppercase()).unwrap_or(false)
}

fn fold_unary_op(op: DslUnaryOp, value: DslValue) -> DslValue {
    match (op, value) {
        (DslUnaryOp::Neg, DslValue::Int(value)) => {
            value
                .checked_neg()
                .map(DslValue::Int)
                .unwrap_or_else(|| DslValue::UnaryOp {
                    op,
                    value: Box::new(DslValue::Int(value)),
                })
        }
        (DslUnaryOp::BitNot, DslValue::Int(value)) => DslValue::Int(!value),
        (DslUnaryOp::BoolNot, DslValue::Bool(value)) => DslValue::Bool(!value),
        (op, value) => DslValue::UnaryOp {
            op,
            value: Box::new(value),
        },
    }
}

fn fold_int_binop(op: DslIntBinOp, left: DslValue, right: DslValue) -> DslValue {
    let (DslValue::Int(left_value), DslValue::Int(right_value)) = (&left, &right) else {
        return simplify_int_binop(op, left, right);
    };
    let Some(folded) = eval_const_int_binop(op, *left_value as i32, *right_value as i32) else {
        return simplify_int_binop(op, left, right);
    };
    if folded < i16::MIN as i32 || folded > i16::MAX as i32 {
        return simplify_int_binop(op, left, right);
    }
    DslValue::Int(folded as i16)
}

fn simplify_int_binop(op: DslIntBinOp, left: DslValue, right: DslValue) -> DslValue {
    let left_int = value_int_literal(&left);
    let right_int = value_int_literal(&right);
    match op {
        DslIntBinOp::Add => {
            if right_int == Some(0) {
                return left;
            }
            if left_int == Some(0) {
                return right;
            }
        }
        DslIntBinOp::Sub => {
            if right_int == Some(0) {
                return left;
            }
            if left_int == Some(0) {
                return fold_unary_op(DslUnaryOp::Neg, right);
            }
        }
        DslIntBinOp::Mul => {
            if right_int == Some(1) {
                return left;
            }
            if left_int == Some(1) {
                return right;
            }
        }
        DslIntBinOp::Div => {
            if right_int == Some(1) {
                return left;
            }
        }
        DslIntBinOp::And => {
            if right_int == Some(-1) {
                return left;
            }
            if left_int == Some(-1) {
                return right;
            }
        }
        DslIntBinOp::Or | DslIntBinOp::Xor => {
            if right_int == Some(0) {
                return left;
            }
            if left_int == Some(0) {
                return right;
            }
        }
        DslIntBinOp::Shl | DslIntBinOp::Shr | DslIntBinOp::Ushr => {
            if right_int == Some(0) {
                return left;
            }
        }
        DslIntBinOp::Rem => {}
    }
    DslValue::IntBinOp {
        op,
        left: Box::new(left),
        right: Box::new(right),
    }
}

fn value_int_literal(value: &DslValue) -> Option<i16> {
    let DslValue::Int(value) = value else {
        return None;
    };
    Some(*value)
}

fn eval_const_int_binop(op: DslIntBinOp, left: i32, right: i32) -> Option<i32> {
    let value = match op {
        DslIntBinOp::Add => left.wrapping_add(right),
        DslIntBinOp::Sub => left.wrapping_sub(right),
        DslIntBinOp::Mul => left.wrapping_mul(right),
        DslIntBinOp::Div => {
            if right == 0 {
                return None;
            }
            left.wrapping_div(right)
        }
        DslIntBinOp::Rem => {
            if right == 0 {
                return None;
            }
            left.wrapping_rem(right)
        }
        DslIntBinOp::And => left & right,
        DslIntBinOp::Or => left | right,
        DslIntBinOp::Xor => left ^ right,
        DslIntBinOp::Shl => left.wrapping_shl((right & 0x1f) as u32),
        DslIntBinOp::Shr => left.wrapping_shr((right & 0x1f) as u32),
        DslIntBinOp::Ushr => ((left as u32).wrapping_shr((right & 0x1f) as u32)) as i32,
    };
    Some(value)
}

fn is_local_ident(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first == '$' {
        return false;
    }
    first == '_' || first.is_ascii_alphabetic()
}
