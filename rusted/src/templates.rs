//! Persisted local configuration templates, separate from subscription tokens.
//! The templates table is intentionally simple so older databases can migrate
//! without rewriting subscription rows or losing user YAML.
use crate::store::{now, random_token};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Template {
    pub id: String,
    pub name: String,
    pub description: String,
    pub manual_yaml: String,
    pub rules_text: String,
    pub built_in: bool,
    pub updated_at: i64,
}

/// Portable native template format. IDs and timestamps are deliberately
/// excluded: an import creates a new local SQLite record.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableTemplate {
    pub format: String,
    pub version: u32,
    pub name: String,
    pub description: String,
    pub manual_yaml: String,
    pub rules_text: String,
}
impl PortableTemplate {
    pub fn from_template(template: &Template) -> Self {
        Self { format: "subboost-rs-template".into(), version: 1,
            name: template.name.clone(), description: template.description.clone(),
            manual_yaml: template.manual_yaml.clone(), rules_text: template.rules_text.clone() }
    }
    pub fn into_input(self) -> Result<TemplateInput, String> {
        if self.format != "subboost-rs-template" || self.version != 1 {
            return Err("Unsupported template format or version".into());
        }
        Ok(TemplateInput {
            name: self.name, description: self.description,
            manual_yaml: self.manual_yaml, rules_text: self.rules_text,
        })
    }
}

#[derive(Deserialize, Serialize)]
pub struct TemplateInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub manual_yaml: String,
    #[serde(default)]
    pub rules_text: String,
}

const BUILTINS: [(&str, &str, &str, &str, &str); 3] = [
    ("standard", "Standard · 标准", "基础规则、自动测速与手动选择", "", "MATCH,Proxy"),
    ("lan-direct", "LAN Direct · 局域网直连", "私有地址直连，其他流量走代理", "",
     "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nIP-CIDR,172.16.0.0/12,DIRECT,no-resolve\nIP-CIDR,192.168.0.0/16,DIRECT,no-resolve\nMATCH,Proxy"),
    ("minimal", "Minimal · 极简", "最少额外规则，减少路由器规则开销", "", "MATCH,Proxy"),
];

fn builtin(id: &str, name: &str, description: &str, yaml: &str, rules: &str) -> Template {
    Template {
        id: format!("builtin-{id}"), name: name.to_owned(),
        description: description.to_owned(), manual_yaml: yaml.to_owned(),
        rules_text: rules.to_owned(), built_in: true, updated_at: 0,
    }
}

fn parse_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Template> {
    Ok(Template { id: row.get(0)?, name: row.get(1)?,
        description: row.get(2)?, manual_yaml: row.get(3)?,
        rules_text: row.get(4)?, built_in: false, updated_at: row.get(5)? })
}

pub fn initialize(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS templates(
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            manual_yaml TEXT NOT NULL DEFAULT '',
            rules_text TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL
        );"
    )
}

pub fn list(db: &Connection) -> rusqlite::Result<Vec<Template>> {
    let mut result: Vec<_> = BUILTINS.iter()
        .map(|&(id, name, desc, yaml, rules)| builtin(id, name, desc, yaml, rules))
        .collect();
    let mut stmt = db.prepare(
        "SELECT id,name,description,manual_yaml,rules_text,updated_at FROM templates
         ORDER BY updated_at DESC,id"
    )?;
    let rows = stmt.query_map([], parse_row)?;
    result.extend(rows.collect::<rusqlite::Result<Vec<_>>>()?);
    Ok(result)
}

pub fn get(db: &Connection, id: &str) -> rusqlite::Result<Option<Template>> {
    if let Some((name, desc, yaml, rules)) = BUILTINS.iter().find_map(
        |&(key, name, desc, yaml, rules)| {
            (format!("builtin-{key}") == id).then_some((name, desc, yaml, rules))
        }
    ) {
        return Ok(Some(builtin(&id["builtin-".len()..], name, desc, yaml, rules)));
    }
    db.query_row(
        "SELECT id,name,description,manual_yaml,rules_text,updated_at
         FROM templates WHERE id=?1",
        params![id],parse_row,
    ).optional()
}

pub fn create(db: &Connection, input: TemplateInput) -> rusqlite::Result<Template> {
    let id=random_token()[..18].to_string();
    db.execute("INSERT INTO templates
        (id,name,description,manual_yaml,rules_text,updated_at)
        VALUES (?1,?2,?3,?4,?5,?6)",
        params![id,input.name,input.description,input.manual_yaml,input.rules_text,now()])?;
    get(db,&id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)
}

pub fn update(db: &Connection, id: &str, input: TemplateInput) -> rusqlite::Result<Option<Template>> {
    if id.starts_with("builtin-") { return Ok(None); }
    let changed=db.execute(
        "UPDATE templates SET name=?2,description=?3,manual_yaml=?4,
         rules_text=?5,updated_at=?6 WHERE id=?1",
        params![id,input.name,input.description,input.manual_yaml,input.rules_text,now()])?;
    if changed==0 { return Ok(None); }
    get(db,id)
}

pub fn delete(db: &Connection, id: &str) -> rusqlite::Result<bool> {
    if id.starts_with("builtin-") { return Ok(false); }
    Ok(db.execute("DELETE FROM templates WHERE id=?1",params![id])?!=0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn portable_template_round_trip_creates_a_fresh_identity() {
        let db=Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let original=create(&db,TemplateInput {
            name:"Exported".into(),description:"portable".into(),
            manual_yaml:"dns:\n  enable: true".into(),
            rules_text:"MATCH,DIRECT".into(),
        }).unwrap();
        let payload=PortableTemplate::from_template(&original);
        let serialized=serde_json::to_string(&payload).unwrap();
        let parsed:PortableTemplate=serde_json::from_str(&serialized).unwrap();
        let imported=create(&db,parsed.into_input().unwrap()).unwrap();
        assert_ne!(original.id,imported.id);
        assert_eq!(original.manual_yaml,imported.manual_yaml);
        assert_eq!(original.rules_text,imported.rules_text);
        let mut unsupported=PortableTemplate::from_template(&original);
        unsupported.version=9;
        assert!(unsupported.into_input().is_err());
    }
    #[test]
    fn templates_are_persistent_and_builtins_immutable() {
        let db=Connection::open_in_memory().unwrap();
        initialize(&db).unwrap();
        let list0=list(&db).unwrap();
        assert_eq!(list0.len(),3);
        assert_eq!(get(&db,"builtin-standard").unwrap().unwrap().rules_text,"MATCH,Proxy");
        let item=create(&db,TemplateInput{
            name:"Custom".into(),description:"Test".into(),
            manual_yaml:"dns:\n  enable: true".into(),
            rules_text:"MATCH,DIRECT".into(),
        }).unwrap();
        assert!(!item.built_in);
        assert_eq!(list(&db).unwrap().len(),4);
        assert!(update(&db,"builtin-standard",TemplateInput{
            name:"Tampered".into(),description:String::new(),
            manual_yaml:String::new(),rules_text:String::new(),
        }).unwrap().is_none());
        assert!(!delete(&db,"builtin-standard").unwrap());
        assert_eq!(get(&db,&item.id).unwrap().unwrap().manual_yaml,item.manual_yaml);
        assert!(delete(&db,&item.id).unwrap());
        assert_eq!(list(&db).unwrap().len(),3);
    }
}
