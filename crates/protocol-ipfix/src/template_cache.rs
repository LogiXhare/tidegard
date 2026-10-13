use std::collections::HashMap;

use crate::error::DecodeError;
use crate::record::DataRecord;
use crate::template::Template;

/// Sampling parameters learned from an Options Template's data records
/// (RFC 7011 §8.1 mentions the *sampling* Information Elements; IANA's
/// IPFIX Information Element registry documents IE 34 `samplingInterval`
/// and IE 35 `samplingAlgorithm` — both public specifications, no
/// proprietary source involved).
///
/// This is deliberately just data extraction — actually *applying* a
/// sampling multiplier to counters belongs in the Traffic Aggregator
/// (Phase 3, see docs/roadmap.md), not the protocol decoder. Storing it
/// here means the collector doesn't have to re-parse Options Templates
/// itself to make the value available downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SamplingInfo {
    pub sampling_interval: Option<u32>,
    pub sampling_algorithm: Option<u8>,
}

/// The most templates one cache holds: one exporter's observation
/// domain. Routers define tens; a cache full of hundreds is an exporter
/// misbehaving or someone else's datagrams (Phase 9D, ADR 0056).
pub const MAX_TEMPLATES: usize = 512;

/// The most field specifiers one cache holds across all its templates.
/// With [`MAX_TEMPLATES`] it bounds a cache's memory to about 128 KiB,
/// whatever an exporter sends; a router's templates total a few hundred.
pub const MAX_TEMPLATE_FIELDS: usize = 8_192;

const IE_SAMPLING_INTERVAL: u16 = 34;
const IE_SAMPLING_ALGORITHM: u16 = 35;

/// Caches Template and Options Template records for a single exporter
/// observation domain, plus any sampling information learned from that
/// domain's Options Template data records.
///
/// One `TemplateCache` corresponds to one (exporter, observation domain
/// ID) pair — template IDs are only meaningful within that scope (RFC
/// 7011 §8.1). The caller (`wetechinetmon-collector`) owns one instance
/// per exporter/domain and is responsible for evicting caches for
/// exporters that have gone quiet, and for detecting exporter restarts
/// (a sequence-number reset) and clearing the affected cache — this
/// crate only stores whatever it's told.
#[derive(Debug, Default)]
pub struct TemplateCache {
    templates: HashMap<u16, Template>,
    /// Field specifiers across every cached template, against
    /// [`MAX_TEMPLATE_FIELDS`].
    fields: usize,
    sampling: SamplingInfo,
}

impl TemplateCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records or replaces a Template/Options Template. Per RFC 7011
    /// §8.1, a template with the same ID as an existing one is a
    /// (re)definition, not an error — the old definition is simply
    /// replaced. Detecting *unexpected* template churn as a signal (e.g.
    /// for the `unknown_templates_total`-style metrics in
    /// docs/security-principles.md) is the collector's job, since only it
    /// has the context of "is this an exporter restart or something
    /// suspicious."
    ///
    /// Refuses a template that would take the cache past
    /// [`MAX_TEMPLATES`] or [`MAX_TEMPLATE_FIELDS`], and keeps what it
    /// had: the limits are what keep an exporter, or anyone who can send
    /// to the collector's port, from growing it without bound.
    pub fn insert(&mut self, template: Template) -> Result<(), DecodeError> {
        let (templates, replaced) = match self.templates.get(&template.template_id) {
            Some(old) => (self.templates.len(), old.fields.len()),
            None => (self.templates.len() + 1, 0),
        };
        let fields = self.fields - replaced + template.fields.len();
        if templates > MAX_TEMPLATES || fields > MAX_TEMPLATE_FIELDS {
            return Err(DecodeError::TemplateLimit {
                template_id: template.template_id,
            });
        }
        self.fields = fields;
        self.templates.insert(template.template_id, template);
        Ok(())
    }

    /// Forgets one template: a Template Withdrawal (RFC 7011 §8.1).
    pub fn remove(&mut self, template_id: u16) {
        if let Some(old) = self.templates.remove(&template_id) {
            self.fields -= old.fields.len();
        }
    }

    /// Field specifiers across every cached template.
    pub fn field_count(&self) -> usize {
        self.fields
    }

    pub fn get(&self, template_id: u16) -> Option<&Template> {
        self.templates.get(&template_id)
    }

    pub fn contains(&self, template_id: u16) -> bool {
        self.templates.contains_key(&template_id)
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    /// Clears every cached template. Call this when a sequence-number
    /// reset (or other signal) indicates the exporter has restarted —
    /// its previously assigned template IDs may now mean something
    /// different (RFC 7011 §8.1 explicitly warns readers not to assume
    /// template IDs are stable across an exporter restart).
    pub fn clear(&mut self) {
        self.templates.clear();
        self.fields = 0;
        self.sampling = SamplingInfo::default();
    }

    /// Inspects a decoded Options Template data record for known
    /// sampling Information Elements and updates the cached
    /// `SamplingInfo` accordingly. Fields this cache doesn't recognize
    /// are ignored, not treated as an error — an Options Template can
    /// legitimately carry many fields WetechiNetMon doesn't interpret
    /// yet.
    pub fn observe_options_data(&mut self, record: &DataRecord) {
        for field in &record.fields {
            match field.information_element_id {
                IE_SAMPLING_INTERVAL => {
                    if let Some(v) = field.as_u64_be() {
                        self.sampling.sampling_interval = Some(v as u32);
                    }
                }
                IE_SAMPLING_ALGORITHM => {
                    if let Some(v) = field.as_u64_be() {
                        self.sampling.sampling_algorithm = Some(v as u8);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn sampling(&self) -> SamplingInfo {
        self.sampling
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::DecodedField;
    use crate::template::FieldSpecifier;

    fn sample_template(id: u16) -> Template {
        Template {
            template_id: id,
            scope_field_count: 0,
            fields: vec![FieldSpecifier {
                information_element_id: 8,
                field_length: 4,
                enterprise_number: None,
            }],
        }
    }

    fn template_of(id: u16, fields: usize) -> Template {
        Template {
            template_id: id,
            scope_field_count: 0,
            fields: vec![
                FieldSpecifier {
                    information_element_id: 8,
                    field_length: 4,
                    enterprise_number: None,
                };
                fields
            ],
        }
    }

    #[test]
    fn a_template_past_the_count_limit_is_refused_and_the_cache_kept() {
        let mut cache = TemplateCache::new();
        for id in 0..MAX_TEMPLATES {
            cache.insert(template_of(256 + id as u16, 1)).unwrap();
        }
        let next = 256 + MAX_TEMPLATES as u16;
        assert_eq!(
            cache.insert(template_of(next, 1)),
            Err(DecodeError::TemplateLimit { template_id: next })
        );
        assert_eq!(cache.len(), MAX_TEMPLATES);
        assert!(!cache.contains(next));
        // Redefining a template already held needs no room.
        cache.insert(template_of(256, 3)).unwrap();
        assert_eq!(cache.field_count(), MAX_TEMPLATES + 2);
    }

    #[test]
    fn templates_past_the_field_limit_are_refused() {
        let mut cache = TemplateCache::new();
        cache
            .insert(template_of(256, MAX_TEMPLATE_FIELDS - 10))
            .unwrap();
        assert_eq!(
            cache.insert(template_of(257, 11)),
            Err(DecodeError::TemplateLimit { template_id: 257 })
        );
        cache.insert(template_of(257, 10)).unwrap();
        assert_eq!(cache.field_count(), MAX_TEMPLATE_FIELDS);
        // Withdrawing and clearing give the room back.
        cache.remove(256);
        assert_eq!(cache.field_count(), 10);
        cache
            .insert(template_of(258, MAX_TEMPLATE_FIELDS - 10))
            .unwrap();
        cache.clear();
        assert_eq!(cache.field_count(), 0);
    }

    #[test]
    fn insert_and_get_round_trip() {
        let mut cache = TemplateCache::new();
        assert!(cache.is_empty());
        cache.insert(sample_template(256)).unwrap();
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(256));
        assert_eq!(cache.get(256).unwrap().template_id, 256);
        assert!(cache.get(999).is_none());
    }

    #[test]
    fn redefinition_replaces_rather_than_errors() {
        let mut cache = TemplateCache::new();
        cache.insert(sample_template(256)).unwrap();
        let mut replacement = sample_template(256);
        replacement.fields.push(FieldSpecifier {
            information_element_id: 12,
            field_length: 4,
            enterprise_number: None,
        });
        cache.insert(replacement).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(256).unwrap().fields.len(), 2);
    }

    #[test]
    fn clear_drops_templates_and_sampling() {
        let mut cache = TemplateCache::new();
        cache.insert(sample_template(256)).unwrap();
        cache.observe_options_data(&DataRecord {
            template_id: 300,
            fields: vec![DecodedField {
                information_element_id: IE_SAMPLING_INTERVAL,
                enterprise_number: None,
                value: 100u32.to_be_bytes().to_vec(),
            }],
        });
        assert_eq!(cache.sampling().sampling_interval, Some(100));

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.sampling(), SamplingInfo::default());
    }

    #[test]
    fn observe_options_data_ignores_unknown_fields() {
        let mut cache = TemplateCache::new();
        cache.observe_options_data(&DataRecord {
            template_id: 300,
            fields: vec![DecodedField {
                information_element_id: 999, // not a sampling IE
                enterprise_number: None,
                value: vec![1, 2, 3],
            }],
        });
        assert_eq!(cache.sampling(), SamplingInfo::default());
    }
}
