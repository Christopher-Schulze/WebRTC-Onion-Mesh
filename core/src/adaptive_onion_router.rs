//! Adaptive Onion Router für minimale Latenz bei maximaler Anonymität
//!
//! Dieser Router passt die Anzahl der Hops dynamisch an das Bedrohungsmodell an
//! und implementiert parallele Circuit-Konstruktion für optimale Performance.

use crate::{
    peer::PeerId,
    onion::CircuitId,
    error::{zmeshError, zmeshResult},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
    sync::{Arc, atomic::{AtomicU64, Ordering}},
};
use tokio::sync::RwLock;
use rand::Rng;

/// Bedrohungslevel bestimmt die Anzahl der Hops
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Niedrig: 2 Hops - Minimale Latenz für normale Nutzung
    Low,
    /// Mittel: 3 Hops - Standard Tor-Äquivalent
    Medium,
    /// Hoch: 4-5 Hops - Erhöhte Anonymität
    High,
    /// Kritisch: 6+ Hops + Guards - Maximale Anonymität
    Critical,
}

impl ThreatLevel {
    /// Empfohlene Hop-Anzahl für das Bedrohungslevel
    pub fn recommended_hops(&self) -> u8 {
        match self {
            ThreatLevel::Low => 2,
            ThreatLevel::Medium => 3,
            ThreatLevel::High => rand::thread_rng().gen_range(4..=5),
            ThreatLevel::Critical => rand::thread_rng().gen_range(6..=8),
        }
    }
    
    /// Maximale akzeptable Latenz für das Level
    pub fn max_latency(&self) -> Duration {
        match self {
            ThreatLevel::Low => Duration::from_millis(50),
            ThreatLevel::Medium => Duration::from_millis(100),
            ThreatLevel::High => Duration::from_millis(200),
            ThreatLevel::Critical => Duration::from_millis(500),
        }
    }
}

/// Bedrohungseinschätzung basierend auf Netzwerkbedingungen
#[derive(Debug, Clone)]
pub struct ThreatAssessment {
    /// Aktuelles Bedrohungslevel
    pub current_level: ThreatLevel,
    /// Erkannte Angriffe
    pub detected_attacks: Vec<AttackType>,
    /// Netzwerk-Kompromittierung
    pub network_compromise_risk: f64,
    /// Geografische Risikobewertung
    pub geographic_risk: f64,
    /// Letzte Aktualisierung
    pub last_updated: Instant,
}

/// Erkannte Angriffstypen
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackType {
    /// Traffic Analysis
    TrafficAnalysis,
    /// Timing Correlation
    TimingCorrelation,
    /// Node Compromise
    NodeCompromise,
    /// Sybil Attack
    SybilAttack,
    /// DDoS Attack
    DDoSAttack,
}

/// Adaptive Onion Router
pub struct AdaptiveOnionRouter {
    /// Aktuelle Bedrohungseinschätzung
    threat_assessment: Arc<RwLock<ThreatAssessment>>,
    /// Latenz-Budget für Routing-Entscheidungen
    latency_budget: Duration,
    /// Minimale Anonymitätsanforderung
    min_anonymity_level: ThreatLevel,
    /// Parallele Circuit-Konstruktionen
    parallel_constructions: Arc<RwLock<HashMap<CircuitId, CircuitConstruction>>>,
    /// Relay-Auswahl-Engine
    relay_selector: LatencyOptimizedSelector,
    /// Performance-Metriken
    metrics: Arc<AdaptiveRouterMetrics>,
}

/// Circuit-Konstruktion mit parallelen Pfaden
#[derive(Debug)]
struct CircuitConstruction {
    /// Circuit ID
    circuit_id: CircuitId,
    /// Parallel konstruierte Pfade
    parallel_paths: Vec<CircuitPath>,
    /// Startzeit der Konstruktion
    start_time: Instant,
    /// Ziel-Latenz
    target_latency: Duration,
    /// Bedrohungslevel für diesen Circuit
    threat_level: ThreatLevel,
}

/// Einzelner Circuit-Pfad
#[derive(Debug, Clone)]
struct CircuitPath {
    /// Pfad-ID
    path_id: u64,
    /// Relay-Kette
    relays: Vec<RelayInfo>,
    /// Geschätzte Latenz
    estimated_latency: Duration,
    /// Konstruktionsstatus
    status: ConstructionStatus,
    /// Qualitätsbewertung
    quality_score: f64,
}

/// Status der Circuit-Konstruktion
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConstructionStatus {
    /// Initialisierung
    Initializing,
    /// In Konstruktion
    Building,
    /// Erfolgreich konstruiert
    Ready,
    /// Fehlgeschlagen
    Failed,
    /// Timeout
    TimedOut,
}

/// Relay-Information für Auswahl
#[derive(Debug, Clone)]
struct RelayInfo {
    /// Peer ID
    peer_id: PeerId,
    /// Geografische Position
    geographic_location: GeographicLocation,
    /// Bandbreiten-Kapazität
    bandwidth_capacity: u64,
    /// Historische Latenz
    historical_latency: Duration,
    /// Zuverlässigkeitsbewertung
    reliability_score: f64,
    /// Letzte Verfügbarkeitsprüfung
    last_seen: Instant,
}

/// Geografische Position
#[derive(Debug, Clone)]
struct GeographicLocation {
    /// Breitengrad
    latitude: f64,
    /// Längengrad
    longitude: f64,
    /// Land
    country: String,
    /// Region
    region: String,
}

/// Latenz-optimierte Relay-Auswahl
struct LatencyOptimizedSelector {
    /// Verfügbare Relays
    available_relays: Arc<RwLock<HashMap<PeerId, RelayInfo>>>,
    /// Geografische Optimierung
    geographic_optimizer: GeographicOptimizer,
    /// Bandbreiten-Bewertung
    bandwidth_assessor: BandwidthAssessor,
    /// Latenz-Prädiktor
    latency_predictor: LatencyPredictor,
}

/// Geografische Optimierung für Relay-Auswahl
struct GeographicOptimizer {
    /// Bevorzugte Regionen
    preferred_regions: Vec<String>,
    /// Zu vermeidende Länder
    avoided_countries: Vec<String>,
    /// Diversitäts-Anforderungen
    diversity_requirements: DiversityRequirements,
}

/// Diversitäts-Anforderungen
#[derive(Debug, Clone)]
struct DiversityRequirements {
    /// Minimale geografische Distanz zwischen Relays
    min_geographic_distance: f64,
    /// Maximale Relays pro Land
    max_relays_per_country: u8,
    /// Minimale AS-Diversität
    min_as_diversity: u8,
}

/// Bandbreiten-Bewertung
struct BandwidthAssessor {
    /// Minimale Bandbreite
    min_bandwidth: u64,
    /// Bandbreiten-Gewichtung
    bandwidth_weight: f64,
    /// Auslastungs-Schwellwert
    utilization_threshold: f64,
}

/// Latenz-Prädiktor
struct LatencyPredictor {
    /// Historische Latenz-Daten
    historical_data: HashMap<PeerId, Vec<LatencyMeasurement>>,
    /// Vorhersage-Modell
    prediction_model: PredictionModel,
}

/// Latenz-Messung
#[derive(Debug, Clone)]
struct LatencyMeasurement {
    /// Gemessene Latenz
    latency: Duration,
    /// Zeitstempel
    timestamp: Instant,
    /// Paketgröße
    packet_size: usize,
    /// Netzwerkbedingungen
    network_conditions: NetworkConditions,
}

/// Netzwerkbedingungen
#[derive(Debug, Clone)]
struct NetworkConditions {
    /// Netzwerk-Auslastung
    network_load: f64,
    /// Tageszeit
    time_of_day: u8,
    /// Wochentag
    day_of_week: u8,
}

/// Vorhersage-Modell für Latenz
enum PredictionModel {
    /// Einfacher gleitender Durchschnitt
    SimpleMovingAverage { window_size: usize },
    /// Exponentiell gewichteter Durchschnitt
    ExponentialWeightedAverage { alpha: f64 },
    /// Lineare Regression
    LinearRegression { coefficients: Vec<f64> },
}

/// Performance-Metriken für adaptiven Router
#[derive(Debug, Default)]
struct AdaptiveRouterMetrics {
    /// Anzahl konstruierter Circuits
    circuits_built: AtomicU64,
    /// Durchschnittliche Konstruktionszeit
    avg_construction_time: AtomicU64,
    /// Erfolgsrate der Circuit-Konstruktion
    construction_success_rate: AtomicU64,
    /// Latenz-Verbesserung durch Optimierung
    latency_improvement: AtomicU64,
    /// Anzahl paralleler Konstruktionen
    parallel_constructions_count: AtomicU64,
}

impl AdaptiveOnionRouter {
    /// Erstelle neuen adaptiven Onion Router
    pub fn new(
        latency_budget: Duration,
        min_anonymity_level: ThreatLevel,
    ) -> Self {
        let threat_assessment = Arc::new(RwLock::new(ThreatAssessment {
            current_level: ThreatLevel::Medium,
            detected_attacks: Vec::new(),
            network_compromise_risk: 0.1,
            geographic_risk: 0.1,
            last_updated: Instant::now(),
        }));
        
        Self {
            threat_assessment,
            latency_budget,
            min_anonymity_level,
            parallel_constructions: Arc::new(RwLock::new(HashMap::new())),
            relay_selector: LatencyOptimizedSelector::new(),
            metrics: Arc::new(AdaptiveRouterMetrics::default()),
        }
    }
    
    /// Konstruiere optimalen Circuit mit parallelen Pfaden
    pub async fn build_optimal_circuit(
        &mut self,
        destination: PeerId,
    ) -> zmeshResult<CircuitId> {
        let start_time = Instant::now();
        let circuit_id = CircuitId::new();
        
        // Aktuelle Bedrohungseinschätzung abrufen
        let threat_assessment = self.threat_assessment.read().await.clone();
        let threat_level = self.determine_threat_level(&threat_assessment).await;
        
        // Anzahl paralleler Pfade basierend auf Bedrohungslevel
        let parallel_paths_count = match threat_level {
            ThreatLevel::Low => 2,
            ThreatLevel::Medium => 3,
            ThreatLevel::High => 4,
            ThreatLevel::Critical => 5,
        };
        
        // Parallele Circuit-Konstruktion starten
        let construction = CircuitConstruction {
            circuit_id,
            parallel_paths: Vec::new(),
            start_time,
            target_latency: threat_level.max_latency(),
            threat_level,
        };
        
        self.parallel_constructions.write().await
            .insert(circuit_id, construction);
        
        // Parallele Pfade konstruieren
        let mut construction_tasks = Vec::new();
        
        for path_id in 0..parallel_paths_count {
            let relay_selector = self.relay_selector.clone();
            let threat_level = threat_level;
            let destination = destination;
            
            let task = tokio::spawn(async move {
                relay_selector.build_path(
                    path_id as u64,
                    destination,
                    threat_level,
                ).await
            });
            
            construction_tasks.push(task);
        }
        
        // Warten auf den ersten erfolgreichen Pfad
        let fastest_path = self.wait_for_fastest_path(construction_tasks).await?;
        
        // Circuit als bereit markieren
        self.finalize_circuit(circuit_id, fastest_path).await?;
        
        // Metriken aktualisieren
        self.update_metrics(start_time).await;
        
        Ok(circuit_id)
    }
    
    /// Bestimme aktuelles Bedrohungslevel
    async fn determine_threat_level(
        &self,
        assessment: &ThreatAssessment,
    ) -> ThreatLevel {
        // Basis-Level aus Assessment
        let mut level = assessment.current_level;
        
        // Erhöhe Level bei erkannten Angriffen
        if !assessment.detected_attacks.is_empty() {
            level = match level {
                ThreatLevel::Low => ThreatLevel::Medium,
                ThreatLevel::Medium => ThreatLevel::High,
                ThreatLevel::High => ThreatLevel::Critical,
                ThreatLevel::Critical => ThreatLevel::Critical,
            };
        }
        
        // Berücksichtige Netzwerk-Kompromittierungsrisiko
        if assessment.network_compromise_risk > 0.5 {
            level = ThreatLevel::Critical;
        } else if assessment.network_compromise_risk > 0.3 {
            level = match level {
                ThreatLevel::Low => ThreatLevel::High,
                ThreatLevel::Medium => ThreatLevel::High,
                _ => level,
            };
        }
        
        // Stelle sicher, dass Minimum-Level eingehalten wird
        if (level as u8) < (self.min_anonymity_level as u8) {
            level = self.min_anonymity_level;
        }
        
        level
    }
    
    /// Warte auf den schnellsten erfolgreichen Pfad
    async fn wait_for_fastest_path(
        &self,
        mut tasks: Vec<tokio::task::JoinHandle<zmeshResult<CircuitPath>>>,
    ) -> zmeshResult<CircuitPath> {
        while !tasks.is_empty() {
            let (result, _index, remaining) = futures::future::select_all(tasks).await;
            tasks = remaining;
            
            match result {
                Ok(Ok(path)) => return Ok(path),
                Ok(Err(_)) => continue, // Dieser Pfad ist fehlgeschlagen
                Err(_) => continue, // Task-Fehler
            }
        }
        
        Err(zmeshError::Network("Alle parallelen Pfade fehlgeschlagen".to_string()))
    }
    
    /// Finalisiere Circuit-Konstruktion
    async fn finalize_circuit(
        &mut self,
        circuit_id: CircuitId,
        winning_path: CircuitPath,
    ) -> zmeshResult<()> {
        // Circuit in aktive Liste eintragen
        // Implementation würde hier den Circuit aktivieren
        
        // Parallele Konstruktion entfernen
        self.parallel_constructions.write().await.remove(&circuit_id);
        
        Ok(())
    }
    
    /// Aktualisiere Performance-Metriken
    async fn update_metrics(&self, start_time: Instant) {
        let construction_time = start_time.elapsed();
        
        self.metrics.circuits_built.fetch_add(1, Ordering::Relaxed);
        
        // Durchschnittliche Konstruktionszeit aktualisieren
        let current_avg = self.metrics.avg_construction_time.load(Ordering::Relaxed);
        let new_avg = if current_avg == 0 {
            construction_time.as_millis() as u64
        } else {
            (current_avg + construction_time.as_millis() as u64) / 2
        };
        self.metrics.avg_construction_time.store(new_avg, Ordering::Relaxed);
    }
    
    /// Aktualisiere Bedrohungseinschätzung
    pub async fn update_threat_assessment(
        &mut self,
        new_attacks: Vec<AttackType>,
        network_compromise_risk: f64,
        geographic_risk: f64,
    ) {
        let mut assessment = self.threat_assessment.write().await;
        
        assessment.detected_attacks = new_attacks;
        assessment.network_compromise_risk = network_compromise_risk;
        assessment.geographic_risk = geographic_risk;
        assessment.last_updated = Instant::now();
        
        // Automatische Level-Anpassung
        assessment.current_level = if network_compromise_risk > 0.7 {
            ThreatLevel::Critical
        } else if network_compromise_risk > 0.4 || !assessment.detected_attacks.is_empty() {
            ThreatLevel::High
        } else if network_compromise_risk > 0.2 {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        };
    }
    
    /// Hole aktuelle Performance-Metriken
    pub fn get_metrics(&self) -> AdaptiveRouterMetrics {
        AdaptiveRouterMetrics {
            circuits_built: AtomicU64::new(
                self.metrics.circuits_built.load(Ordering::Relaxed)
            ),
            avg_construction_time: AtomicU64::new(
                self.metrics.avg_construction_time.load(Ordering::Relaxed)
            ),
            construction_success_rate: AtomicU64::new(
                self.metrics.construction_success_rate.load(Ordering::Relaxed)
            ),
            latency_improvement: AtomicU64::new(
                self.metrics.latency_improvement.load(Ordering::Relaxed)
            ),
            parallel_constructions_count: AtomicU64::new(
                self.metrics.parallel_constructions_count.load(Ordering::Relaxed)
            ),
        }
    }
}

impl LatencyOptimizedSelector {
    fn new() -> Self {
        Self {
            available_relays: Arc::new(RwLock::new(HashMap::new())),
            geographic_optimizer: GeographicOptimizer::new(),
            bandwidth_assessor: BandwidthAssessor::new(),
            latency_predictor: LatencyPredictor::new(),
        }
    }
    
    fn clone(&self) -> Self {
        Self {
            available_relays: self.available_relays.clone(),
            geographic_optimizer: self.geographic_optimizer.clone(),
            bandwidth_assessor: self.bandwidth_assessor.clone(),
            latency_predictor: self.latency_predictor.clone(),
        }
    }
    
    async fn build_path(
        &self,
        path_id: u64,
        destination: PeerId,
        threat_level: ThreatLevel,
    ) -> zmeshResult<CircuitPath> {
        let hop_count = threat_level.recommended_hops();
        let mut relays = Vec::new();
        
        // Wähle optimale Relays für den Pfad
        for hop in 0..hop_count {
            let relay = self.select_optimal_relay(hop, &relays, destination).await?;
            relays.push(relay);
        }
        
        // Schätze Gesamtlatenz
        let estimated_latency = self.estimate_path_latency(&relays).await;
        
        // Berechne Qualitätsbewertung
        let quality_score = self.calculate_quality_score(&relays, estimated_latency).await;
        
        Ok(CircuitPath {
            path_id,
            relays,
            estimated_latency,
            status: ConstructionStatus::Ready,
            quality_score,
        })
    }
    
    async fn select_optimal_relay(
        &self,
        hop_index: u8,
        existing_relays: &[RelayInfo],
        destination: PeerId,
    ) -> zmeshResult<RelayInfo> {
        let available_relays = self.available_relays.read().await;
        
        // Filtere verfügbare Relays basierend auf Diversitäts-Anforderungen
        let candidates: Vec<_> = available_relays
            .values()
            .filter(|relay| self.is_suitable_relay(relay, existing_relays, hop_index))
            .collect();
        
        if candidates.is_empty() {
            return Err(zmeshError::Network("Keine geeigneten Relays verfügbar".to_string()));
        }
        
        // Wähle bestes Relay basierend auf Latenz und anderen Faktoren
        let best_relay = candidates
            .into_iter()
            .max_by(|a, b| {
                let score_a = self.calculate_relay_score(a, hop_index);
                let score_b = self.calculate_relay_score(b, hop_index);
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap();
        
        Ok(best_relay.clone())
    }
    
    fn is_suitable_relay(
        &self,
        relay: &RelayInfo,
        existing_relays: &[RelayInfo],
        hop_index: u8,
    ) -> bool {
        // Prüfe Diversitäts-Anforderungen
        self.geographic_optimizer.check_diversity(relay, existing_relays) &&
        self.bandwidth_assessor.meets_requirements(relay) &&
        self.is_relay_available(relay)
    }
    
    fn calculate_relay_score(&self, relay: &RelayInfo, hop_index: u8) -> f64 {
        let latency_score = 1.0 / (relay.historical_latency.as_millis() as f64 + 1.0);
        let bandwidth_score = (relay.bandwidth_capacity as f64).log10() / 10.0;
        let reliability_score = relay.reliability_score;
        
        // Gewichtung basierend auf Hop-Position
        let latency_weight = if hop_index == 0 { 0.5 } else { 0.3 };
        let bandwidth_weight = 0.3;
        let reliability_weight = 0.2;
        
        latency_weight * latency_score +
        bandwidth_weight * bandwidth_score +
        reliability_weight * reliability_score
    }
    
    fn is_relay_available(&self, relay: &RelayInfo) -> bool {
        relay.last_seen.elapsed() < Duration::from_secs(300) // 5 Minuten
    }
    
    async fn estimate_path_latency(&self, relays: &[RelayInfo]) -> Duration {
        let total_latency: u64 = relays
            .iter()
            .map(|relay| relay.historical_latency.as_millis() as u64)
            .sum();
        
        Duration::from_millis(total_latency)
    }
    
    async fn calculate_quality_score(
        &self,
        relays: &[RelayInfo],
        estimated_latency: Duration,
    ) -> f64 {
        let latency_score = 1.0 / (estimated_latency.as_millis() as f64 + 1.0);
        let diversity_score = self.geographic_optimizer.calculate_diversity_score(relays);
        let reliability_score = relays.iter()
            .map(|r| r.reliability_score)
            .sum::<f64>() / relays.len() as f64;
        
        (latency_score + diversity_score + reliability_score) / 3.0
    }
}

// Implementierung der Helper-Strukturen
impl GeographicOptimizer {
    fn new() -> Self {
        Self {
            preferred_regions: vec!["EU".to_string(), "NA".to_string()],
            avoided_countries: vec!["CN".to_string(), "RU".to_string()],
            diversity_requirements: DiversityRequirements {
                min_geographic_distance: 1000.0, // km
                max_relays_per_country: 1,
                min_as_diversity: 2,
            },
        }
    }
    
    fn clone(&self) -> Self {
        Self {
            preferred_regions: self.preferred_regions.clone(),
            avoided_countries: self.avoided_countries.clone(),
            diversity_requirements: self.diversity_requirements.clone(),
        }
    }
    
    fn check_diversity(&self, relay: &RelayInfo, existing_relays: &[RelayInfo]) -> bool {
        // Prüfe Land-Diversität
        let same_country_count = existing_relays
            .iter()
            .filter(|r| r.geographic_location.country == relay.geographic_location.country)
            .count();
        
        if same_country_count >= self.diversity_requirements.max_relays_per_country as usize {
            return false;
        }
        
        // Prüfe geografische Distanz
        for existing in existing_relays {
            let distance = self.calculate_distance(
                &relay.geographic_location,
                &existing.geographic_location,
            );
            
            if distance < self.diversity_requirements.min_geographic_distance {
                return false;
            }
        }
        
        true
    }
    
    fn calculate_distance(&self, loc1: &GeographicLocation, loc2: &GeographicLocation) -> f64 {
        // Vereinfachte Haversine-Formel
        let lat1_rad = loc1.latitude.to_radians();
        let lat2_rad = loc2.latitude.to_radians();
        let delta_lat = (loc2.latitude - loc1.latitude).to_radians();
        let delta_lon = (loc2.longitude - loc1.longitude).to_radians();
        
        let a = (delta_lat / 2.0).sin().powi(2) +
                lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
        
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        
        6371.0 * c // Erdradius in km
    }
    
    fn calculate_diversity_score(&self, relays: &[RelayInfo]) -> f64 {
        if relays.len() < 2 {
            return 1.0;
        }
        
        let mut total_distance = 0.0;
        let mut pair_count = 0;
        
        for i in 0..relays.len() {
            for j in (i + 1)..relays.len() {
                total_distance += self.calculate_distance(
                    &relays[i].geographic_location,
                    &relays[j].geographic_location,
                );
                pair_count += 1;
            }
        }
        
        let avg_distance = total_distance / pair_count as f64;
        (avg_distance / 10000.0).min(1.0) // Normalisiert auf 0-1
    }
}

impl BandwidthAssessor {
    fn new() -> Self {
        Self {
            min_bandwidth: 10_000_000, // 10 Mbps
            bandwidth_weight: 0.3,
            utilization_threshold: 0.8,
        }
    }
    
    fn clone(&self) -> Self {
        Self {
            min_bandwidth: self.min_bandwidth,
            bandwidth_weight: self.bandwidth_weight,
            utilization_threshold: self.utilization_threshold,
        }
    }
    
    fn meets_requirements(&self, relay: &RelayInfo) -> bool {
        relay.bandwidth_capacity >= self.min_bandwidth
    }
}

impl LatencyPredictor {
    fn new() -> Self {
        Self {
            historical_data: HashMap::new(),
            prediction_model: PredictionModel::ExponentialWeightedAverage { alpha: 0.1 },
        }
    }
    
    fn clone(&self) -> Self {
        Self {
            historical_data: self.historical_data.clone(),
            prediction_model: match &self.prediction_model {
                PredictionModel::SimpleMovingAverage { window_size } => {
                    PredictionModel::SimpleMovingAverage { window_size: *window_size }
                },
                PredictionModel::ExponentialWeightedAverage { alpha } => {
                    PredictionModel::ExponentialWeightedAverage { alpha: *alpha }
                },
                PredictionModel::LinearRegression { coefficients } => {
                    PredictionModel::LinearRegression { coefficients: coefficients.clone() }
                },
            },
        }
    }
}