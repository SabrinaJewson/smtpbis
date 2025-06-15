use rustyknife::NomResult;
use rustyknife::nom::branch::alt;
use rustyknife::nom::combinator::map;
use rustyknife::rfc5321::Command as BaseCommand;
use rustyknife::rfc5321::UTF8Policy;
use rustyknife::rfc5321::bdat_command;
use rustyknife::rfc5321::command as base_command;
use rustyknife::rfc5321::starttls_command;
use rustyknife::xforward::Param as XforwardParam;
use rustyknife::xforward::command as xforward_command;

#[derive(Debug)]
pub enum Command {
    Base(BaseCommand),
    Ext(Ext),
}

#[derive(Debug)]
pub enum Ext {
    StartTls,
    Bdat(u64, bool),
    XForward(Vec<XforwardParam>),
}

pub fn command<P: UTF8Policy>(input: &[u8]) -> NomResult<'_, Command> {
    alt((
        map(base_command::<P>, Command::Base),
        map(starttls_command, |_| Command::Ext(Ext::StartTls)),
        map(bdat_command, |(size, last)| {
            Command::Ext(Ext::Bdat(size, last))
        }),
        map(xforward_command, |params| {
            Command::Ext(Ext::XForward(params))
        }),
    ))(input)
}
