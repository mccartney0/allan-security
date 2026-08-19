use anyhow::{anyhow, Result};
use object::{read::File as ObjectFile, BinaryFormat, NameOrOrdinal, Object, ObjectSection};
use serde::{Deserialize, Serialize};

pub const PE_PARSER_ENGINE_KEY: &str = "pe-object-0.40-v1";
pub const MAX_PE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PE_SECTIONS: usize = 96;
pub const MAX_PE_IMPORTS: usize = 100_000;
pub const MAX_SECTION_SAMPLE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PeParseStatus {
    Parsed,
    ParsedWithWarnings,
    Malformed,
    TooLarge,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeSectionReport {
    pub name: String,
    pub address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub characteristics: String,
    pub entropy: Option<f64>,
    pub raw_range_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeImportReport {
    pub library: String,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
}

impl Default for PeParseStatus {
    fn default() -> Self {
        Self::Parsed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeStaticReport {
    pub status: PeParseStatus,
    pub machine: Option<u16>,
    pub architecture: String,
    pub is_64: Option<bool>,
    pub timestamp: Option<u32>,
    pub entry_point: Option<u64>,
    pub sections: Vec<PeSectionReport>,
    pub imports: Vec<PeImportReport>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeKind {
    NotPe,
    Pe,
}

pub fn classify(bytes: &[u8]) -> PeKind {
    if bytes.starts_with(b"MZ") {
        PeKind::Pe
    } else {
        PeKind::NotPe
    }
}

pub fn analyze_bytes(bytes: &[u8]) -> Result<Option<PeStaticReport>> {
    if classify(bytes) == PeKind::NotPe {
        return Ok(None);
    }
    if bytes.len() > MAX_PE_BYTES {
        return Ok(Some(PeStaticReport {
            status: PeParseStatus::TooLarge,
            warnings: vec![format!("PE excede o limite de {} bytes", MAX_PE_BYTES)],
            ..Default::default()
        }));
    }

    let machine = read_u16_le(
        bytes,
        pe_offset(bytes).and_then(|offset| offset.checked_add(4)),
    );
    let timestamp = read_u32_le(
        bytes,
        pe_offset(bytes).and_then(|offset| offset.checked_add(8)),
    );

    let file = match ObjectFile::parse(bytes) {
        Ok(file) if file.format() == BinaryFormat::Pe => file,
        Ok(_) => return Ok(None),
        Err(error) => {
            return Ok(Some(PeStaticReport {
                status: PeParseStatus::Malformed,
                machine,
                architecture: "unknown".to_string(),
                is_64: None,
                timestamp,
                warnings: vec![format!("PE malformado: {error}")],
                ..Default::default()
            }))
        }
    };

    let mut warnings = Vec::new();
    let sections_iter = file.sections();
    let mut sections = Vec::new();
    for section in sections_iter {
        if sections.len() >= MAX_PE_SECTIONS {
            warnings.push(format!(
                "mais de {} seções; lista truncada",
                MAX_PE_SECTIONS
            ));
            break;
        }
        let name = section
            .name()
            .map(str::to_owned)
            .unwrap_or_else(|_| "<invalid-name>".to_string());
        let (raw_offset, raw_size) = section.file_range().unwrap_or((0, 0));
        let raw_end = raw_offset.checked_add(raw_size);
        let raw_range_valid = raw_end.is_some_and(|end| end <= bytes.len() as u64);
        if !raw_range_valid && raw_size != 0 {
            warnings.push(format!("seção {name} possui range raw fora do arquivo"));
        }
        let entropy = section
            .data()
            .ok()
            .and_then(|data| shannon_entropy(&data[..data.len().min(MAX_SECTION_SAMPLE_BYTES)]));
        sections.push(PeSectionReport {
            name,
            address: section.address(),
            virtual_size: section.size(),
            raw_offset,
            raw_size,
            characteristics: format!("{:?}", section.flags()),
            entropy,
            raw_range_valid,
        });
    }

    let mut imports = Vec::new();
    match file.imports() {
        Ok(imports_iter) => {
            for import in imports_iter {
                if imports.len() >= MAX_PE_IMPORTS {
                    warnings.push(format!(
                        "mais de {} imports; lista truncada",
                        MAX_PE_IMPORTS
                    ));
                    break;
                }
                let import = match import {
                    Ok(import) => import,
                    Err(error) => {
                        warnings.push(format!("import inválido ignorado: {error}"));
                        continue;
                    }
                };
                let library = String::from_utf8_lossy(import.library()).to_string();
                let (name, ordinal) = match import.name() {
                    NameOrOrdinal::Name(name) => {
                        (Some(String::from_utf8_lossy(name).to_string()), None)
                    }
                    NameOrOrdinal::Ordinal(ordinal) => (None, Some(ordinal)),
                };
                imports.push(PeImportReport {
                    library,
                    name,
                    ordinal,
                });
            }
        }
        Err(error) => warnings.push(format!("tabela de imports indisponível: {error}")),
    }

    let status = if warnings.is_empty() {
        PeParseStatus::Parsed
    } else {
        PeParseStatus::ParsedWithWarnings
    };
    Ok(Some(PeStaticReport {
        status,
        machine,
        architecture: format!("{:?}", file.architecture()),
        is_64: Some(file.is_64()),
        timestamp,
        entry_point: Some(file.entry()),
        sections,
        imports,
        warnings,
    }))
}

fn pe_offset(bytes: &[u8]) -> Option<usize> {
    let offset = read_u32_le(bytes, Some(0x3c))? as usize;
    if offset.checked_add(4)? <= bytes.len() {
        Some(offset)
    } else {
        None
    }
}

fn read_u16_le(bytes: &[u8], offset: Option<usize>) -> Option<u16> {
    let offset = offset?;
    let end = offset.checked_add(2)?;
    let value = bytes.get(offset..end)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32_le(bytes: &[u8], offset: Option<usize>) -> Option<u32> {
    let offset = offset?;
    let end = offset.checked_add(4)?;
    let value = bytes.get(offset..end)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn shannon_entropy(bytes: &[u8]) -> Option<f64> {
    if bytes.is_empty() {
        return None;
    }
    let mut counts = [0_u64; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    let entropy = counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / total;
            -probability * probability.log2()
        })
        .sum();
    Some(entropy)
}

pub fn validate_report(report: &PeStaticReport) -> Result<()> {
    if report.sections.len() > MAX_PE_SECTIONS {
        return Err(anyhow!("relatório excede o limite de seções"));
    }
    if report.imports.len() > MAX_PE_IMPORTS {
        return Err(anyhow!("relatório excede o limite de imports"));
    }
    if report
        .sections
        .iter()
        .any(|section| !section.raw_range_valid && section.raw_size != 0)
    {
        return Err(anyhow!("relatório contém range raw inválido"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_pe_is_not_analyzed() {
        assert_eq!(classify(b"hello"), PeKind::NotPe);
        assert!(analyze_bytes(b"hello").unwrap().is_none());
    }

    #[test]
    fn truncated_mz_is_malformed_without_panic() {
        let report = analyze_bytes(b"MZ").unwrap().unwrap();
        assert_eq!(report.status, PeParseStatus::Malformed);
    }

    #[test]
    fn oversized_mz_is_rejected_before_parsing() {
        let mut bytes = vec![b'M'; MAX_PE_BYTES + 1];
        bytes[1] = b'Z';
        let report = analyze_bytes(&bytes).unwrap().unwrap();
        assert_eq!(report.status, PeParseStatus::TooLarge);
    }

    #[test]
    fn entropy_is_bounded_and_deterministic() {
        let entropy = shannon_entropy(&[0, 1, 2, 3]).unwrap();
        assert!((entropy - 2.0).abs() < f64::EPSILON);
    }
}
