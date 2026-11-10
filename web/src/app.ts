import Alpine from 'alpinejs';
import Chart from 'chart.js/auto';

interface NotificationItem {
    id: number;
    message: string;
    type: 'success' | 'error' | 'info';
}

interface TrafficFlow {
    src_ip: string;
    dst_ip: string;
    src_port: number;
    dst_port: number;
    proto: number;
    proto_name?: string;
    ip_version?: number;
    bytes: number;
    packets: number;
    direction?: 'IN' | 'OUT';
    duration_sec?: number;
    last_seen_sec?: number;
    blocked?: boolean;
}

interface AttackItem {
    id: number | string;
    timestamp: string;
    unix_timestamp?: number;
    src_ip: string;
    attack_type: string;
    protocol: string;
    severity: number;
    severity_label?: string;
    packets: number;
    bytes: number;
    dropped_packets: number;
    dropped_bytes: number;
    peak_pps: number;
    duration: number;
    blocked: boolean;
    status: string;
}

interface AutoBlockItem {
    ip: string;
    attack_id: number;
    attack_type: string;
    protocol: string;
    blocked_packets: number;
    blocked_bytes: number;
    peak_pps: number;
    remaining_sec: number;
    first_seen: string;
    last_seen: string;
}

interface FirewallRule {
    id?: number;
    rule_key?: string;
    ip: string;
    port: number;
    proto: string;
    proto_num?: number;
    action: number;
    description?: string;
    enabled?: boolean;
}

interface IpListEntry {
    id: number;
    ip_address: string;
    cidr_range: number;
    list_type: 'whitelist' | 'blacklist';
    reason: string;
    expires_at: number;
    created_at: number;
}

interface GeoRule {
    id?: number;
    country_code: string;
    action: string;
    priority?: number;
}

interface SecurityEvent {
    id: number;
    timestamp: number;
    event_type: string;
    severity: number;
    process_name: string;
    pid: number;
    ppid: number;
    command: string;
    binary_path: string;
    parent_binary: string;
    action: string;
    policy_name: string;
    src_ip?: string;
    dst_ip?: string;
    dst_port?: number;
    file_path?: string;
    file_operation?: string;
}

interface SecurityPolicy {
    name: string;
    filename: string;
    deployed: boolean;
    size?: number;
    modified?: number;
}

interface AttackCorrelation {
    id: number;
    timestamp: number;
    attack_type: string;
    confidence_score: number;
    network_event_id: number;
    security_event_id: number;
    source_ip: string;
    description: string;
    details: string;
    created_at: number;
}

interface ApiKeyItem {
    id: number;
    name: string;
    prefix: string;
    permissions: string;
    last_used_at: number;
    expires_at: number;
    created_at: number;
}

class WSClient {
    private ws: WebSocket | null = null;
    private port: number;
    private reconnectInterval = 3000;
    private readonly maxReconnectInterval = 15000;
    private reconnectTimer: number | null = null;
    private closedManually = false;

    constructor(port: number) {
        this.port = port;
        if (localStorage.getItem('token')) {
            this.connect();
        }
    }

    private buildUrl(): string {
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const token = localStorage.getItem('token') || '';
        const tokenParam = token ? `?token=${encodeURIComponent(token)}` : '';
        if (
            window.location.protocol === 'https:' ||
            window.location.port === '' ||
            window.location.port === '80' ||
            window.location.port === '443'
        ) {
            return `${proto}//${window.location.host}/ws${tokenParam}`;
        }
        return `${proto}//${window.location.hostname}:${this.port}/${tokenParam}`;
    }

    getPort(): number {
        return this.port;
    }

    setPort(nextPort: number) {
        if (!nextPort || nextPort === this.port) return;
        this.port = nextPort;
        if (this.reconnectTimer !== null) {
            window.clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        if (this.ws) {
            const old = this.ws;
            this.ws = null;
            old.onclose = null;
            old.close();
        }
        if (localStorage.getItem('token')) {
            this.connect();
        }
    }

    ensureConnected() {
        if (!this.ws && !this.closedManually && localStorage.getItem('token')) {
            this.connect();
        }
    }

    connect() {
        if (this.closedManually || !localStorage.getItem('token')) return;
        if (this.reconnectTimer !== null) {
            window.clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        try {
            window.dispatchEvent(new CustomEvent('ws-status', { detail: { connected: false, connecting: true } }));
            const ws = new WebSocket(this.buildUrl(), 'lws-cyrenus-protocol');
            this.ws = ws;

            ws.onopen = () => {
                this.reconnectInterval = 3000;
                window.dispatchEvent(new CustomEvent('ws-status', { detail: { connected: true, connecting: false } }));
            };

            ws.onmessage = (event) => {
                try {
                    const payload = JSON.parse(event.data);
                    window.dispatchEvent(new CustomEvent('ws-message', { detail: payload }));
                } catch (e) {
                    console.error('Invalid WS JSON payload', e);
                }
            };

            ws.onerror = () => {
                window.dispatchEvent(new CustomEvent('ws-status', { detail: { connected: false, connecting: false } }));
            };

            ws.onclose = () => {
                this.ws = null;
                window.dispatchEvent(new CustomEvent('ws-status', { detail: { connected: false, connecting: false } }));
                if (!this.closedManually && localStorage.getItem('token')) {
                    const wait = this.reconnectInterval;
                    this.reconnectInterval = Math.min(this.maxReconnectInterval, Math.round(this.reconnectInterval * 1.5));
                    this.reconnectTimer = window.setTimeout(() => this.connect(), wait);
                }
            };
        } catch {
            window.dispatchEvent(new CustomEvent('ws-status', { detail: { connected: false, connecting: false } }));
            if (!this.closedManually && localStorage.getItem('token')) {
                const wait = this.reconnectInterval;
                this.reconnectInterval = Math.min(this.maxReconnectInterval, Math.round(this.reconnectInterval * 1.5));
                this.reconnectTimer = window.setTimeout(() => this.connect(), wait);
            }
        }
    }

    close() {
        this.closedManually = true;
        if (this.reconnectTimer !== null) {
            window.clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        if (this.ws) {
            this.ws.onclose = null;
            this.ws.close();
            this.ws = null;
        }
    }
}

function guessDefaultWsPort(): number {
    if (window.location.port) {
        const p = Number(window.location.port);
        if (!Number.isNaN(p) && p > 0 && p < 65535) return p + 1;
    }
    return 8182;
}

const wsClient = new WSClient(guessDefaultWsPort());

document.addEventListener('alpine:init', () => {
    Alpine.data('dashboard_data', () => {
        // Keep Chart.js instance outside Alpine reactivity proxy
        let chartInstance: Chart | null = null;
        let pollTickCounter = 0;
        let trafficAutoTimer: number | null = null;

        const HISTORY_POINTS = 60;
        const chartLabels: string[] = Array(HISTORY_POINTS).fill('');
        const passedPpsHistory: number[] = Array(HISTORY_POINTS).fill(0);
        const droppedPpsHistory: number[] = Array(HISTORY_POINTS).fill(0);
        const passedMbpsHistory: number[] = Array(HISTORY_POINTS).fill(0);
        const droppedMbpsHistory: number[] = Array(HISTORY_POINTS).fill(0);

        return {
            // Navigation & Global UI State
            currentPage: 'dashboard' as string,
            sidebarOpen: false,
            username: localStorage.getItem('username') || 'Admin',
            wsConnected: false,
            wsConnecting: true,
            isRefreshing: false,
            chartMode: 'pps' as 'pps' | 'mbps',
            sponsorshipModalOpen: false,
            notifications: [] as NotificationItem[],

            // Dashboard KPIs & System Stats
            stats: {
                pps: 0,
                bps: 0,
                passed_pps: 0,
                passed_bps: 0,
                dropped_pps: 0,
                dropped_bps: 0,
                total_packets: 0,
                passed_packets: 0,
                dropped_packets: 0,
                dropped_bytes: 0,
                active_attacks: 0,
                active_blocks: 0,
                attacks_total: 0
            },
            systemStats: {
                uptime_sec: 0,
                interface: 'eth0',
                xdp_mode: 'Loading...',
                dry_run: false,
                http_port: 8181,
                ws_port: 8182,
                geoip_enabled: false,
                db_size_bytes: 0,
                disk_total_bytes: 0,
                disk_free_bytes: 0,
                disk_used_bytes: 0,
                attacks_total: 0,
                active_attacks: 0,
                active_blocks: 0,
                rules_count: 0,
                whitelist_count: 0,
                blacklist_count: 0,
                geo_rules_count: 0,
                global_stats: {
                    total_packets: 0,
                    total_bytes: 0,
                    passed_packets: 0,
                    passed_bytes: 0,
                    dropped_packets: 0,
                    dropped_bytes: 0,
                    udp_drops: 0,
                    syn_drops: 0,
                    icmp_drops: 0,
                    dns_drops: 0,
                    frag_drops: 0,
                    rule_drops: 0,
                    geo_drops: 0,
                    autoblock_drops: 0,
                    amp_drops: 0,
                    ack_drops: 0,
                    rst_drops: 0,
                    malformed_drops: 0
                }
            },

            // Traffic State
            traffic: [] as TrafficFlow[],
            trafficSearch: '',
            trafficDirection: 'ALL' as 'ALL' | 'IN' | 'OUT',
            trafficSort: 'packets' as 'packets' | 'bytes' | 'last_seen',
            trafficAutoRefresh: true,
            trafficPage: 1,
            itemsPerPage: 15,

            // Attacks & Auto-Blocks State
            attacks: [] as AttackItem[],
            attacksTotal: 0,
            attacksLimit: 25,
            attacksOffset: 0,
            attackSummary: {
                total: 0,
                active: 0,
                mitigated: 0,
                resolved: 0,
                by_type: {} as Record<string, number>
            },
            attackFilters: {
                status: 'all',
                type: 'all',
                search: ''
            },
            blocks: [] as AutoBlockItem[],

            // Rules, IP Lists & GeoIP State
            rulesSubTab: 'firewall' as 'firewall' | 'iplists' | 'geoip',
            rules: [] as FirewallRule[],
            newRule: {
                ip: '',
                port: 0,
                proto: 'all',
                action: 'drop' as 'drop' | 'pass',
                description: ''
            },
            whitelist: [] as IpListEntry[],
            blacklist: [] as IpListEntry[],
            newIpList: {
                ip_address: '',
                cidr_range: 32,
                list_type: 'whitelist' as 'whitelist' | 'blacklist',
                reason: '',
                ttl_sec: 0
            },
            geoRules: [] as GeoRule[],
            newGeoCountry: '',
            geoLookupIp: '',
            geoLookupResult: null as { ip: string; country_code: string; country_name: string; city: string } | null,
            geoLookupError: '',

            // Host Security (Tetragon) State
            securitySubTab: 'events' as 'events' | 'correlations' | 'policies' | 'logs',
            security: {
                events: [] as SecurityEvent[],
                correlations: [] as AttackCorrelation[],
                corrMinConfidence: 0,
                stats: {
                    total_events: 0,
                    critical_alerts: 0,
                    events_blocked: 0,
                    process_exec_events: 0,
                    alerts_generated: 0,
                    tetragon_running: false
                },
                policies: [] as SecurityPolicy[],
                logs: [] as any[],
                filters: {
                    severity: '',
                    eventType: '',
                    search: '',
                    limit: 50
                },
                currentPolicy: { name: '', content: '', isNew: false },
                showModal: false,
                showConfigModal: false,
                tetragonConfigContent: '',
                savingConfig: false
            },

            // Settings & API Keys State
            settings: {
                interface: 'eth0',
                xdp_mode: 'Unknown',
                dry_run: false,
                http_port: 8181,
                ws_port: 8182,
                log_level: 2,
                geoip_enabled: false,
                syn_flood_rate: 500,
                udp_flood_rate: 5000,
                icmp_flood_rate: 100,
                dns_amp_rate: 200,
                max_frags: 15,
                auto_block_enabled: true,
                auto_block_duration_sec: 300,
                global_syn_rate: 5000,
                global_udp_rate: 25000,
                max_dns_response_size: 2048,
                rst_flood_rate: 500,
                ack_flood_rate: 2500,
                synack_flood_rate: 1000
            },
            savingSettings: false,
            apiKeys: [] as ApiKeyItem[],
            newApiKey: { name: '', permissions: 'read,write', expires_in_days: 0 },
            generatedKey: null as string | null,
            keyCopied: false,

            init() {
                if (!localStorage.getItem('token')) {
                    window.location.replace('/login.html');
                    return;
                }

                wsClient.ensureConnected();
                this.initChart();

                // Load initial data in parallel
                this.fetchSystemStats();
                this.fetchSettings();
                this.fetchAttacks(true);
                this.fetchBlocks();
                this.fetchTraffic();
                this.fetchRules();
                this.fetchIpLists();
                this.fetchGeoRules();
                this.fetchSecurityStats();
                this.fetchSecurityCorrelations();
                this.fetchApiKeys();

                // Auto-refresh live traffic while user is viewing Traffic tab
                trafficAutoTimer = window.setInterval(() => {
                    if (this.currentPage === 'traffic' && this.trafficAutoRefresh && !document.hidden) {
                        this.fetchTraffic();
                    }
                }, 3000);

                window.addEventListener('ws-status', (e: Event) => {
                    const detail = (e as CustomEvent).detail || {};
                    this.wsConnected = Boolean(detail.connected);
                    this.wsConnecting = Boolean(detail.connecting);
                });

                window.addEventListener('ws-message', (e: Event) => {
                    const msg = (e as CustomEvent).detail;
                    if (!msg) return;

                    if (msg.type === 'traffic_update' && msg.data) {
                        const d = msg.data;
                        const passedPps = Number(d.passed_pps ?? d.pps) || 0;
                        const droppedPps = Number(d.dropped_pps) || 0;
                        const passedBps = Number(d.passed_bps ?? d.bps) || 0;
                        const droppedBps = Number(d.dropped_bps) || 0;

                        this.stats.pps = Number(d.pps) || 0;
                        this.stats.bps = Number(d.bps) || 0;
                        this.stats.passed_pps = passedPps;
                        this.stats.passed_bps = passedBps;
                        this.stats.dropped_pps = droppedPps;
                        this.stats.dropped_bps = droppedBps;
                        if (d.total_packets !== undefined) this.stats.total_packets = Number(d.total_packets) || 0;
                        if (d.passed_packets !== undefined) this.stats.passed_packets = Number(d.passed_packets) || 0;
                        if (d.dropped_packets !== undefined) this.stats.dropped_packets = Number(d.dropped_packets) || 0;
                        if (d.dropped_bytes !== undefined) this.stats.dropped_bytes = Number(d.dropped_bytes) || 0;
                        if (d.active_attacks !== undefined) this.stats.active_attacks = Number(d.active_attacks) || 0;
                        if (d.active_blocks !== undefined) this.stats.active_blocks = Number(d.active_blocks) || 0;

                        this.pushChartPoint(passedPps, droppedPps, passedBps, droppedBps, Number(d.timestamp) || 0);

                        pollTickCounter++;
                        if (pollTickCounter % 5 === 0 && !document.hidden) {
                            if (this.currentPage === 'dashboard') {
                                this.fetchSystemStats();
                                this.fetchBlocks();
                                this.fetchAttacks(false);
                            } else if (this.currentPage === 'attacks') {
                                this.fetchBlocks();
                                this.fetchAttacks(false);
                            }
                        }
                    } else if (msg.type === 'attack_alert' && msg.data) {
                        const a = msg.data;
                        const statusWord = a.blocked ? 'AUTO-BLOCKED' : 'DETECTED';
                        this.notify(
                            `${a.attack_type || 'Attack'} ${statusWord} from ${a.src_ip} (${this.formatNumber(a.peak_pps || 0)} PPS)`,
                            'error'
                        );
                        this.fetchAttacks(false);
                        this.fetchBlocks();
                        this.fetchSystemStats();
                    } else if (msg.type === 'security_update') {
                        if (this.currentPage === 'security') {
                            this.fetchSecurityEvents();
                            this.fetchSecurityStats();
                        }
                    } else if (msg.type === 'security_alert') {
                        this.notify(`Host Security Alert: ${msg.message || 'Policy triggered'}`, 'error');
                        this.fetchSecurityStats();
                        if (this.currentPage === 'security') {
                            this.fetchSecurityEvents();
                            this.fetchSecurityCorrelations();
                        }
                    } else if (msg.type === 'correlation_alert' && msg.data) {
                        const c = msg.data;
                        const conf = Math.round((Number(c.confidence_score) || 0) * 100);
                        this.notify(`Correlated Threat (${conf}%): ${c.attack_type || 'Intrusion'} — ${c.source_ip || 'host'}`, 'error');
                        if (this.currentPage === 'security') {
                            this.fetchSecurityCorrelations();
                        }
                    }
                });
            },

            async apiFetch(url: string, options: RequestInit = {}): Promise<Response> {
                const token = localStorage.getItem('token');
                const headers = new Headers(options.headers || {});
                if (token) {
                    headers.set('Authorization', `Bearer ${token}`);
                }
                if (options.body && !headers.has('Content-Type')) {
                    headers.set('Content-Type', 'application/json');
                }
                const res = await fetch(url, { ...options, headers });
                if (res.status === 401) {
                    localStorage.removeItem('token');
                    wsClient.close();
                    window.location.replace('/login.html');
                }
                return res;
            },

            async logout() {
                try {
                    await this.apiFetch('/api/v1/auth/logout', { method: 'POST' });
                } catch {
                    // Ignore network failure during logout
                } finally {
                    localStorage.removeItem('token');
                    localStorage.removeItem('username');
                    if (trafficAutoTimer !== null) {
                        window.clearInterval(trafficAutoTimer);
                        trafficAutoTimer = null;
                    }
                    wsClient.close();
                    window.location.replace('/login.html');
                }
            },

            switchPage(page: string) {
                this.currentPage = page;
                this.sidebarOpen = false;
                if (page === 'dashboard') {
                    this.fetchSystemStats();
                    this.fetchBlocks();
                    this.fetchAttacks(true);
                    window.setTimeout(() => {
                        if (chartInstance) {
                            chartInstance.resize();
                            chartInstance.update('none');
                        }
                    }, 50);
                } else if (page === 'traffic') {
                    this.fetchTraffic();
                } else if (page === 'attacks') {
                    this.fetchAttacks(false);
                    this.fetchBlocks();
                } else if (page === 'rules') {
                    this.fetchRules();
                    this.fetchIpLists();
                    this.fetchGeoRules();
                } else if (page === 'security') {
                    this.fetchSecurityStats();
                    this.fetchSecurityEvents();
                    this.fetchSecurityCorrelations();
                    this.fetchSecurityPolicies();
                    if (this.securitySubTab === 'logs') this.fetchSecurityLogs();
                } else if (page === 'settings') {
                    this.fetchSettings();
                    this.fetchApiKeys();
                }
            },

            async refreshCurrentPage() {
                this.isRefreshing = true;
                try {
                    if (this.currentPage === 'dashboard') {
                        await Promise.all([this.fetchSystemStats(), this.fetchBlocks(), this.fetchAttacks(false)]);
                    } else if (this.currentPage === 'traffic') {
                        await this.fetchTraffic();
                    } else if (this.currentPage === 'attacks') {
                        await Promise.all([this.fetchAttacks(false), this.fetchBlocks()]);
                    } else if (this.currentPage === 'rules') {
                        await Promise.all([this.fetchRules(), this.fetchIpLists(), this.fetchGeoRules()]);
                    } else if (this.currentPage === 'security') {
                        await Promise.all([
                            this.fetchSecurityStats(),
                            this.fetchSecurityEvents(),
                            this.fetchSecurityCorrelations(),
                            this.fetchSecurityPolicies(),
                            this.securitySubTab === 'logs' ? this.fetchSecurityLogs() : Promise.resolve()
                        ]);
                    } else if (this.currentPage === 'settings') {
                        await Promise.all([this.fetchSettings(), this.fetchApiKeys()]);
                    }
                } finally {
                    this.isRefreshing = false;
                }
            },

            // --- System Stats & Settings ---
            async fetchSystemStats() {
                try {
                    const res = await this.apiFetch('/api/v1/system/stats');
                    if (!res.ok) return;
                    const data = await res.json();
                    this.systemStats = {
                        ...this.systemStats,
                        ...data,
                        global_stats: {
                            ...this.systemStats.global_stats,
                            ...(data.global_stats || {})
                        }
                    };
                    if (data.ws_port) {
                        wsClient.setPort(Number(data.ws_port));
                    }
                    this.stats.attacks_total = Number(data.attacks_total) || 0;
                    this.stats.active_attacks = Number(data.active_attacks) || 0;
                    this.stats.active_blocks = Number(data.active_blocks) || 0;
                    if (data.global_stats) {
                        this.stats.total_packets = Number(data.global_stats.total_packets) || 0;
                        this.stats.passed_packets = Number(data.global_stats.passed_packets) || 0;
                        this.stats.dropped_packets = Number(data.global_stats.dropped_packets) || 0;
                        this.stats.dropped_bytes = Number(data.global_stats.dropped_bytes) || 0;
                    }
                } catch (e) {
                    console.error('Fetch system stats failed', e);
                }
            },

            async fetchSettings() {
                try {
                    const res = await this.apiFetch('/api/v1/system/settings');
                    if (!res.ok) return;
                    const data = await res.json();
                    this.settings = { ...this.settings, ...data };
                    if (data.ws_port) {
                        wsClient.setPort(Number(data.ws_port));
                    }
                } catch (e) {
                    console.error('Fetch settings failed', e);
                }
            },

            applySettingsPreset(preset: 'strict' | 'balanced' | 'high') {
                if (preset === 'strict') {
                    this.settings.syn_flood_rate = 150;
                    this.settings.udp_flood_rate = 1500;
                    this.settings.icmp_flood_rate = 30;
                    this.settings.dns_amp_rate = 60;
                    this.settings.max_frags = 8;
                    this.settings.auto_block_enabled = true;
                    this.settings.auto_block_duration_sec = 600;
                    this.settings.global_syn_rate = 2000;
                    this.settings.global_udp_rate = 10000;
                    this.settings.max_dns_response_size = 1536;
                    this.settings.rst_flood_rate = 150;
                    this.settings.ack_flood_rate = 1000;
                    this.settings.synack_flood_rate = 300;
                    this.notify('Strict preset staged — click Save & Apply to enforce.', 'info');
                } else if (preset === 'balanced') {
                    this.settings.syn_flood_rate = 500;
                    this.settings.udp_flood_rate = 5000;
                    this.settings.icmp_flood_rate = 100;
                    this.settings.dns_amp_rate = 200;
                    this.settings.max_frags = 15;
                    this.settings.auto_block_enabled = true;
                    this.settings.auto_block_duration_sec = 300;
                    this.settings.global_syn_rate = 5000;
                    this.settings.global_udp_rate = 25000;
                    this.settings.max_dns_response_size = 2048;
                    this.settings.rst_flood_rate = 500;
                    this.settings.ack_flood_rate = 2500;
                    this.settings.synack_flood_rate = 1000;
                    this.notify('Balanced preset staged — click Save & Apply to enforce.', 'info');
                } else {
                    this.settings.syn_flood_rate = 3000;
                    this.settings.udp_flood_rate = 25000;
                    this.settings.icmp_flood_rate = 500;
                    this.settings.dns_amp_rate = 1000;
                    this.settings.max_frags = 50;
                    this.settings.auto_block_enabled = true;
                    this.settings.auto_block_duration_sec = 180;
                    this.settings.global_syn_rate = 25000;
                    this.settings.global_udp_rate = 100000;
                    this.settings.max_dns_response_size = 4096;
                    this.settings.rst_flood_rate = 2500;
                    this.settings.ack_flood_rate = 15000;
                    this.settings.synack_flood_rate = 5000;
                    this.notify('High-Bandwidth preset staged — click Save & Apply to enforce.', 'info');
                }
            },

            async saveSettings() {
                this.savingSettings = true;
                try {
                    const payload = {
                        syn_flood_rate: Number(this.settings.syn_flood_rate),
                        udp_flood_rate: Number(this.settings.udp_flood_rate),
                        icmp_flood_rate: Number(this.settings.icmp_flood_rate),
                        dns_amp_rate: Number(this.settings.dns_amp_rate),
                        max_frags: Number(this.settings.max_frags),
                        auto_block_enabled: Boolean(this.settings.auto_block_enabled),
                        auto_block_duration_sec: Number(this.settings.auto_block_duration_sec),
                        global_syn_rate: Number(this.settings.global_syn_rate),
                        global_udp_rate: Number(this.settings.global_udp_rate),
                        max_dns_response_size: Number(this.settings.max_dns_response_size),
                        rst_flood_rate: Number(this.settings.rst_flood_rate),
                        ack_flood_rate: Number(this.settings.ack_flood_rate),
                        synack_flood_rate: Number(this.settings.synack_flood_rate)
                    };
                    const res = await this.apiFetch('/api/v1/system/settings', {
                        method: 'POST',
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.notify('Protection thresholds saved and applied to kernel', 'success');
                        await this.fetchSettings();
                    } else {
                        this.notify(data.error || 'Failed to save settings', 'error');
                    }
                } catch {
                    this.notify('Network error while saving settings', 'error');
                } finally {
                    this.savingSettings = false;
                }
            },

            // --- Live Traffic ---
            async fetchTraffic() {
                try {
                    const res = await this.apiFetch('/api/v1/traffic/stats');
                    if (!res.ok) return;
                    const data = await res.json();
                    this.traffic = Array.isArray(data) ? data : [];
                    const maxPage = this.totalPages();
                    if (this.trafficPage > maxPage) {
                        this.trafficPage = maxPage;
                    }
                } catch (e) {
                    console.error('Fetch traffic failed', e);
                    this.traffic = [];
                }
            },

            get filteredTraffic(): TrafficFlow[] {
                const q = this.trafficSearch.trim().toLowerCase();
                let list = this.traffic.filter((flow) => {
                    if (this.trafficDirection !== 'ALL' && flow.direction !== this.trafficDirection) {
                        return false;
                    }
                    if (!q) return true;
                    const protoLabel = (flow.proto_name || this.protoToName(flow.proto)).toLowerCase();
                    return (
                        (flow.src_ip && flow.src_ip.toLowerCase().includes(q)) ||
                        (flow.dst_ip && flow.dst_ip.toLowerCase().includes(q)) ||
                        String(flow.src_port).includes(q) ||
                        String(flow.dst_port).includes(q) ||
                        protoLabel.includes(q)
                    );
                });

                list = [...list].sort((a, b) => {
                    if (this.trafficSort === 'bytes') return (b.bytes || 0) - (a.bytes || 0);
                    if (this.trafficSort === 'last_seen') return (a.last_seen_sec || 0) - (b.last_seen_sec || 0);
                    return (b.packets || 0) - (a.packets || 0);
                });

                return list;
            },

            get paginatedTraffic(): TrafficFlow[] {
                const start = (this.trafficPage - 1) * this.itemsPerPage;
                return this.filteredTraffic.slice(start, start + this.itemsPerPage);
            },

            totalPages(): number {
                return Math.max(1, Math.ceil(this.filteredTraffic.length / this.itemsPerPage));
            },

            nextPage() {
                if (this.trafficPage < this.totalPages()) this.trafficPage++;
            },

            prevPage() {
                if (this.trafficPage > 1) this.trafficPage--;
            },

            trafficRangeText(): string {
                const total = this.filteredTraffic.length;
                if (total === 0) return '0 of 0 flows';
                const start = (this.trafficPage - 1) * this.itemsPerPage + 1;
                const end = Math.min(this.trafficPage * this.itemsPerPage, total);
                return `${start} - ${end} of ${total} flows`;
            },

            // --- Attacks & Active Auto-Blocks ---
            async fetchAttacks(resetOffset = false) {
                if (resetOffset) this.attacksOffset = 0;
                try {
                    const params = new URLSearchParams();
                    params.set('limit', String(this.attacksLimit));
                    params.set('offset', String(this.attacksOffset));
                    if (this.attackFilters.status && this.attackFilters.status !== 'all') {
                        params.set('status', this.attackFilters.status);
                    }
                    if (this.attackFilters.type && this.attackFilters.type !== 'all') {
                        params.set('attack_type', this.attackFilters.type);
                    }
                    if (this.attackFilters.search.trim()) {
                        params.set('search', this.attackFilters.search.trim());
                    }

                    const res = await this.apiFetch(`/api/v1/attacks?${params.toString()}`);
                    if (!res.ok) return;
                    const data = await res.json();
                    if (Array.isArray(data)) {
                        this.attacks = data;
                        this.attacksTotal = data.length;
                    } else {
                        this.attacks = Array.isArray(data.attacks) ? data.attacks : [];
                        this.attacksTotal = Number(data.total) || 0;
                        if (data.summary) {
                            this.attackSummary = {
                                total: Number(data.summary.total) || 0,
                                active: Number(data.summary.active) || 0,
                                mitigated: Number(data.summary.mitigated) || 0,
                                resolved: Number(data.summary.resolved) || 0,
                                by_type: data.summary.by_type || {}
                            };
                            this.stats.attacks_total = this.attackSummary.total;
                            this.stats.active_attacks = this.attackSummary.active;
                        }
                    }
                } catch (e) {
                    console.error('Fetch attacks failed', e);
                }
            },

            attacksTotalPages(): number {
                return Math.max(1, Math.ceil(this.attacksTotal / this.attacksLimit));
            },

            attacksCurrentPage(): number {
                return Math.floor(this.attacksOffset / this.attacksLimit) + 1;
            },

            attacksPrevPage() {
                if (this.attacksOffset > 0) {
                    this.attacksOffset = Math.max(0, this.attacksOffset - this.attacksLimit);
                    this.fetchAttacks(false);
                }
            },

            attacksNextPage() {
                if (this.attacksOffset + this.attacksLimit < this.attacksTotal) {
                    this.attacksOffset += this.attacksLimit;
                    this.fetchAttacks(false);
                }
            },

            async resolveAttack(attack: AttackItem) {
                try {
                    const res = await this.apiFetch(`/api/v1/attacks/${encodeURIComponent(String(attack.id))}/resolve`, {
                        method: 'POST'
                    });
                    if (res.ok) {
                        this.notify(`Attack from ${attack.src_ip} marked resolved`, 'success');
                        await Promise.all([this.fetchAttacks(false), this.fetchSystemStats()]);
                    } else {
                        const err = await res.json().catch(() => ({}));
                        this.notify(err.error || 'Failed to resolve attack', 'error');
                    }
                } catch {
                    this.notify('Failed to resolve attack', 'error');
                }
            },

            async clearAttacks() {
                if (!confirm('Clear all recorded attack history and active live counters?')) return;
                try {
                    const res = await this.apiFetch('/api/v1/attacks', { method: 'DELETE' });
                    if (res.ok) {
                        this.notify('Attack history cleared', 'success');
                        await Promise.all([this.fetchAttacks(true), this.fetchSystemStats()]);
                    } else {
                        const err = await res.json().catch(() => ({}));
                        this.notify(err.error || 'Failed to clear attack history', 'error');
                    }
                } catch {
                    this.notify('Failed to clear attack history', 'error');
                }
            },

            async fetchBlocks() {
                try {
                    const res = await this.apiFetch('/api/v1/blocks');
                    if (!res.ok) return;
                    const data = await res.json();
                    this.blocks = Array.isArray(data.blocks) ? data.blocks : [];
                    this.stats.active_blocks = this.blocks.length;
                } catch (e) {
                    console.error('Fetch blocks failed', e);
                }
            },

            async unblockIP(ip: string) {
                try {
                    const res = await this.apiFetch(`/api/v1/blocks/${encodeURIComponent(ip)}`, {
                        method: 'DELETE'
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.notify(`Unblocked ${ip}`, 'success');
                        await Promise.all([this.fetchBlocks(), this.fetchAttacks(false), this.fetchSystemStats()]);
                    } else {
                        this.notify(data.error || `Failed to unblock ${ip}`, 'error');
                    }
                } catch {
                    this.notify(`Failed to unblock ${ip}`, 'error');
                }
            },

            async promoteBlockToBlacklist(ip: string) {
                const defaultCidr = ip.includes(':') ? 128 : 32;
                try {
                    const res = await this.apiFetch('/api/v1/iplists', {
                        method: 'POST',
                        body: JSON.stringify({
                            ip_address: ip,
                            cidr_range: defaultCidr,
                            list_type: 'blacklist',
                            reason: 'Promoted from dynamic auto-block',
                            ttl_sec: 0
                        })
                    });
                    if (res.ok) {
                        this.notify(`${ip} added to permanent blacklist`, 'success');
                        await Promise.all([this.fetchIpLists(), this.fetchSystemStats()]);
                    } else {
                        const err = await res.json().catch(() => ({}));
                        this.notify(err.error || `Failed to blacklist ${ip}`, 'error');
                    }
                } catch {
                    this.notify(`Failed to blacklist ${ip}`, 'error');
                }
            },

            attackDroppedPercent(a: AttackItem): number {
                const total = Number(a.packets) || 0;
                const dropped = Number(a.dropped_packets) || 0;
                if (total <= 0) return a.blocked ? 100 : 0;
                return Math.min(100, Math.round((dropped / total) * 100));
            },

            // --- Quick IP Actions ---
            async blockIP(ip: string) {
                if (!ip || ip === '0.0.0.0' || ip === '::') {
                    this.notify('Cannot block unspecified aggregate IP', 'error');
                    return;
                }
                try {
                    const res = await this.apiFetch('/api/v1/rules', {
                        method: 'POST',
                        body: JSON.stringify({
                            ip,
                            port: 0,
                            proto: 'all',
                            action: 'drop',
                            description: 'Manual block from UI'
                        })
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.notify(`Blocked ${ip} (All Ports & Protocols)`, 'success');
                        await Promise.all([this.fetchRules(), this.fetchTraffic(), this.fetchSystemStats()]);
                    } else {
                        this.notify(data.error || `Failed to block ${ip}`, 'error');
                    }
                } catch {
                    this.notify(`Failed to block ${ip}`, 'error');
                }
            },

            async whitelistIP(ip: string, reason = 'Whitelisted via Dashboard UI') {
                if (!ip || ip === '0.0.0.0' || ip === '::') {
                    this.notify('Cannot whitelist unspecified IP', 'error');
                    return;
                }
                const defaultCidr = ip.includes(':') ? 128 : 32;
                try {
                    const res = await this.apiFetch('/api/v1/iplists', {
                        method: 'POST',
                        body: JSON.stringify({
                            ip_address: ip,
                            cidr_range: defaultCidr,
                            list_type: 'whitelist',
                            reason,
                            ttl_sec: 0
                        })
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.notify(`Whitelisted ${ip}/${defaultCidr} (auto-block lifted)`, 'success');
                        await Promise.all([this.fetchIpLists(), this.fetchBlocks(), this.fetchAttacks(false), this.fetchSystemStats()]);
                    } else {
                        this.notify(data.error || `Failed to whitelist ${ip}`, 'error');
                    }
                } catch {
                    this.notify(`Failed to whitelist ${ip}`, 'error');
                }
            },

            // --- Firewall Rules ---
            async fetchRules() {
                try {
                    const res = await this.apiFetch('/api/v1/rules');
                    if (!res.ok) return;
                    const data = await res.json();
                    this.rules = Array.isArray(data) ? data : [];
                } catch (e) {
                    console.error('Fetch rules failed', e);
                }
            },

            async addRule() {
                try {
                    const payload = {
                        ip: this.newRule.ip.trim(),
                        port: Number(this.newRule.port) || 0,
                        proto: this.newRule.proto,
                        action: this.newRule.action,
                        description: this.newRule.description.trim()
                    };
                    const res = await this.apiFetch('/api/v1/rules', {
                        method: 'POST',
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.notify('Firewall rule deployed', 'success');
                        this.newRule = { ip: '', port: 0, proto: 'all', action: 'drop', description: '' };
                        await Promise.all([this.fetchRules(), this.fetchSystemStats()]);
                    } else {
                        this.notify(data.error || 'Failed to add rule', 'error');
                    }
                } catch {
                    this.notify('Network error while deploying rule', 'error');
                }
            },

            async deleteRule(rule: FirewallRule) {
                if (!confirm(`Delete ${rule.action === 1 ? 'DROP' : 'PASS'} rule for ${rule.ip}?`)) return;
                try {
                    const protoMap: Record<string, number> = { ALL: 0, TCP: 6, UDP: 17, ICMP: 1, ICMPV6: 58 };
                    const protoNum = rule.proto_num !== undefined ? rule.proto_num : (protoMap[String(rule.proto).toUpperCase()] ?? 0);
                    const key = rule.rule_key || `${rule.ip}_${rule.port}_${protoNum}`;
                    const res = await this.apiFetch(`/api/v1/rules/${encodeURIComponent(key)}`, {
                        method: 'DELETE'
                    });
                    if (res.ok) {
                        this.notify('Rule deleted', 'success');
                        await Promise.all([this.fetchRules(), this.fetchSystemStats()]);
                    } else {
                        const err = await res.json().catch(() => ({}));
                        this.notify(err.error || 'Failed to delete rule', 'error');
                    }
                } catch {
                    this.notify('Failed to delete rule', 'error');
                }
            },

            // --- IP Lists (Whitelist & Blacklist CIDRs) ---
            async fetchIpLists() {
                try {
                    const [wlRes, blRes] = await Promise.all([
                        this.apiFetch('/api/v1/iplists/whitelist'),
                        this.apiFetch('/api/v1/iplists/blacklist')
                    ]);
                    if (wlRes.ok) {
                        const wl = await wlRes.json();
                        this.whitelist = Array.isArray(wl) ? wl : [];
                    }
                    if (blRes.ok) {
                        const bl = await blRes.json();
                        this.blacklist = Array.isArray(bl) ? bl : [];
                    }
                } catch (e) {
                    console.error('Fetch IP lists failed', e);
                }
            },

            async addIpListEntry() {
                try {
                    const payload = {
                        ip_address: this.newIpList.ip_address.trim(),
                        cidr_range: Number(this.newIpList.cidr_range),
                        list_type: this.newIpList.list_type,
                        reason: this.newIpList.reason.trim(),
                        ttl_sec: Number(this.newIpList.ttl_sec) || 0
                    };
                    const res = await this.apiFetch('/api/v1/iplists', {
                        method: 'POST',
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.notify(`Added ${data.ip_address}/${data.cidr_range} to ${data.list_type}`, 'success');
                        this.newIpList = {
                            ip_address: '',
                            cidr_range: 32,
                            list_type: this.newIpList.list_type,
                            reason: '',
                            ttl_sec: 0
                        };
                        await Promise.all([this.fetchIpLists(), this.fetchBlocks(), this.fetchSystemStats()]);
                    } else {
                        this.notify(data.error || 'Failed to add IP entry', 'error');
                    }
                } catch {
                    this.notify('Network error adding IP list entry', 'error');
                }
            },

            async deleteIpListEntry(id: number) {
                try {
                    const res = await this.apiFetch(`/api/v1/iplists/${id}`, { method: 'DELETE' });
                    if (res.ok) {
                        this.notify('IP entry removed', 'success');
                        await Promise.all([this.fetchIpLists(), this.fetchSystemStats()]);
                    } else {
                        const err = await res.json().catch(() => ({}));
                        this.notify(err.error || 'Failed to delete IP entry', 'error');
                    }
                } catch {
                    this.notify('Failed to delete IP entry', 'error');
                }
            },

            // --- GeoIP ---
            async fetchGeoRules() {
                try {
                    const res = await this.apiFetch('/api/v1/geoip/rules');
                    if (!res.ok) return;
                    const data = await res.json();
                    this.geoRules = Array.isArray(data) ? data : [];
                } catch (e) {
                    console.error('Fetch GeoIP rules failed', e);
                }
            },

            async addGeoRule(codeOverride?: string) {
                const code = (codeOverride || this.newGeoCountry).trim().toUpperCase();
                if (!code || code.length !== 2) {
                    this.notify('Enter a valid 2-letter ISO country code (e.g. CN, RU)', 'error');
                    return;
                }
                try {
                    const res = await this.apiFetch('/api/v1/geoip/rules', {
                        method: 'POST',
                        body: JSON.stringify({ country_code: code })
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.notify(`Blocked country ${code}`, 'success');
                        if (!codeOverride) this.newGeoCountry = '';
                        await Promise.all([this.fetchGeoRules(), this.fetchSystemStats()]);
                    } else {
                        this.notify(data.error || `Failed to block ${code}`, 'error');
                    }
                } catch {
                    this.notify('Network error adding GeoIP rule', 'error');
                }
            },

            async deleteGeoRule(code: string) {
                try {
                    const res = await this.apiFetch(`/api/v1/geoip/rules/${encodeURIComponent(code)}`, {
                        method: 'DELETE'
                    });
                    if (res.ok) {
                        this.notify(`Unblocked country ${code}`, 'success');
                        await Promise.all([this.fetchGeoRules(), this.fetchSystemStats()]);
                    } else {
                        const err = await res.json().catch(() => ({}));
                        this.notify(err.error || `Failed to remove ${code}`, 'error');
                    }
                } catch {
                    this.notify(`Failed to remove ${code}`, 'error');
                }
            },

            async lookupGeoIp() {
                const ip = this.geoLookupIp.trim();
                this.geoLookupResult = null;
                this.geoLookupError = '';
                if (!ip) return;
                try {
                    const res = await this.apiFetch(`/api/v1/geoip/lookup/${encodeURIComponent(ip)}`);
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.geoLookupResult = data;
                    } else {
                        this.geoLookupError = data.error || 'Country lookup failed';
                    }
                } catch {
                    this.geoLookupError = 'Network error looking up IP';
                }
            },

            // --- Host Security (Tetragon) ---
            get filteredSecurityEvents(): SecurityEvent[] {
                const q = this.security.filters.search.trim().toLowerCase();
                if (!q) return this.security.events;
                return this.security.events.filter((ev) =>
                    (ev.process_name && ev.process_name.toLowerCase().includes(q)) ||
                    (ev.binary_path && ev.binary_path.toLowerCase().includes(q)) ||
                    (ev.command && ev.command.toLowerCase().includes(q)) ||
                    (ev.policy_name && ev.policy_name.toLowerCase().includes(q)) ||
                    (ev.event_type && ev.event_type.toLowerCase().includes(q))
                );
            },

            async fetchSecurityStats() {
                try {
                    const res = await this.apiFetch('/api/v1/security/stats');
                    if (!res.ok) return;
                    this.security.stats = await res.json();
                } catch (e) {
                    console.error('Security stats failed', e);
                }
            },

            async fetchSecurityEvents() {
                try {
                    const params = new URLSearchParams();
                    params.set('limit', String(this.security.filters.limit));
                    if (this.security.filters.severity) params.set('severity', this.security.filters.severity);
                    if (this.security.filters.eventType) params.set('event_type', this.security.filters.eventType);

                    const res = await this.apiFetch(`/api/v1/security/events?${params.toString()}`);
                    if (!res.ok) return;
                    const data = await res.json();
                    this.security.events = data.events || [];
                } catch (e) {
                    console.error('Security events failed', e);
                }
            },

            async fetchSecurityPolicies() {
                try {
                    const res = await this.apiFetch('/api/v1/security/policies');
                    if (!res.ok) return;
                    const data = await res.json();
                    this.security.policies = data.policies || [];
                } catch (e) {
                    console.error('Security policies failed', e);
                }
            },

            async fetchSecurityLogs() {
                try {
                    const res = await this.apiFetch('/api/v1/security/logs?lines=100');
                    if (!res.ok) return;
                    const data = await res.json();
                    this.security.logs = data.logs || [];
                } catch (e) {
                    console.error('Security logs failed', e);
                }
            },

            async fetchSecurityCorrelations() {
                try {
                    const minConf = Number(this.security.corrMinConfidence) || 0;
                    const res = await this.apiFetch(`/api/v1/security/correlations?min_confidence=${encodeURIComponent(String(minConf))}&limit=100`);
                    if (!res.ok) return;
                    const data = await res.json();
                    this.security.correlations = Array.isArray(data.correlations) ? data.correlations : [];
                } catch (e) {
                    console.error('Security correlations failed', e);
                }
            },

            async openTetragonConfigModal() {
                this.security.tetragonConfigContent = '';
                this.security.showConfigModal = true;
                try {
                    const res = await this.apiFetch('/api/v1/security/config');
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.security.tetragonConfigContent = data.content || '';
                    } else {
                        this.security.tetragonConfigContent = 'enable-process-cred: true\nenable-process-ns: true\n';
                        this.notify(data.error || 'Tetragon config not found yet — prefilled starter YAML', 'info');
                    }
                } catch {
                    this.notify('Failed to fetch Tetragon configuration', 'error');
                }
            },

            async saveTetragonConfig() {
                this.security.savingConfig = true;
                try {
                    const res = await this.apiFetch('/api/v1/security/config', {
                        method: 'POST',
                        body: JSON.stringify({ content: this.security.tetragonConfigContent })
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.notify(data.message || 'Tetragon configuration saved', 'success');
                        this.security.showConfigModal = false;
                    } else {
                        this.notify(data.error || 'Failed to save configuration', 'error');
                    }
                } catch {
                    this.notify('Network error saving Tetragon configuration', 'error');
                } finally {
                    this.security.savingConfig = false;
                }
            },

            openNewPolicyModal() {
                this.security.currentPolicy = {
                    name: 'custom-policy',
                    content:
                        'apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: "custom-policy"\nspec:\n  kprobes:\n',
                    isNew: true
                };
                this.security.showModal = true;
            },

            async editPolicy(name: string) {
                try {
                    const res = await this.apiFetch(`/api/v1/security/policy/${encodeURIComponent(name)}`);
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.security.currentPolicy = {
                            name: data.name || name,
                            content: data.content || '',
                            isNew: false
                        };
                        this.security.showModal = true;
                    } else {
                        this.notify(data.error || `Failed to load policy ${name}`, 'error');
                    }
                } catch {
                    this.notify(`Failed to load policy ${name}`, 'error');
                }
            },

            async deployPolicy(name: string) {
                try {
                    const res = await this.apiFetch(`/api/v1/security/policy/${encodeURIComponent(name)}/deploy`, {
                        method: 'POST'
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.notify(data.message || 'Policy deployed', 'success');
                        this.fetchSecurityPolicies();
                    } else {
                        this.notify(data.error || 'Deployment failed', 'error');
                    }
                } catch {
                    this.notify('Deployment failed', 'error');
                }
            },

            async deletePolicy(name: string) {
                if (!confirm(`Delete TracingPolicy "${name}"?`)) return;
                try {
                    const res = await this.apiFetch(`/api/v1/security/policy/${encodeURIComponent(name)}`, {
                        method: 'DELETE'
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.notify(`Policy ${name} deleted`, 'success');
                        this.fetchSecurityPolicies();
                    } else {
                        this.notify(data.error || 'Failed to delete policy', 'error');
                    }
                } catch {
                    this.notify('Failed to delete policy', 'error');
                }
            },

            async savePolicy() {
                const name = this.security.currentPolicy.name.trim();
                if (!name || !/^[A-Za-z0-9_-]+$/.test(name)) {
                    this.notify('Policy name may only contain letters, numbers, dashes, and underscores', 'error');
                    return;
                }
                try {
                    const res = await this.apiFetch(`/api/v1/security/policy/${encodeURIComponent(name)}`, {
                        method: 'POST',
                        body: JSON.stringify({ content: this.security.currentPolicy.content })
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok) {
                        this.notify('Policy saved', 'success');
                        this.security.showModal = false;
                        this.fetchSecurityPolicies();
                    } else {
                        this.notify(data.error || 'Save failed', 'error');
                    }
                } catch {
                    this.notify('Save failed', 'error');
                }
            },

            // --- API Keys ---
            async fetchApiKeys() {
                try {
                    const res = await this.apiFetch('/api/v1/keys');
                    if (!res.ok) return;
                    const data = await res.json();
                    this.apiKeys = Array.isArray(data) ? data : [];
                } catch (e) {
                    console.error('Fetch keys failed', e);
                }
            },

            async createApiKey() {
                if (!this.newApiKey.name.trim()) {
                    this.notify('Please enter a name for the API key', 'error');
                    return;
                }
                try {
                    const res = await this.apiFetch('/api/v1/keys', {
                        method: 'POST',
                        body: JSON.stringify({
                            name: this.newApiKey.name.trim(),
                            permissions: this.newApiKey.permissions,
                            expires_in_days: Number(this.newApiKey.expires_in_days) || 0
                        })
                    });
                    const data = await res.json().catch(() => ({}));
                    if (res.ok && data.api_key) {
                        this.keyCopied = false;
                        this.generatedKey = data.api_key;
                        this.newApiKey = { name: '', permissions: 'read,write', expires_in_days: 0 };
                        await this.fetchApiKeys();
                    } else {
                        this.notify(data.error || 'Failed to generate API key', 'error');
                    }
                } catch {
                    this.notify('Network error creating API key', 'error');
                }
            },

            async deleteApiKey(id: number) {
                if (!confirm('Revoke this API key? Any automation using it will lose access immediately.')) return;
                try {
                    const res = await this.apiFetch('/api/v1/keys', {
                        method: 'DELETE',
                        body: JSON.stringify({ id })
                    });
                    if (res.ok) {
                        this.notify('API key revoked', 'success');
                        await this.fetchApiKeys();
                    } else {
                        const err = await res.json().catch(() => ({}));
                        this.notify(err.error || 'Failed to revoke key', 'error');
                    }
                } catch {
                    this.notify('Failed to revoke key', 'error');
                }
            },

            async copyGeneratedKey() {
                if (!this.generatedKey) return;
                try {
                    await navigator.clipboard.writeText(this.generatedKey);
                    this.keyCopied = true;
                    this.notify('API key copied to clipboard', 'success');
                } catch {
                    this.notify('Copy failed — please select and copy manually', 'info');
                }
            },

            // --- Dual-Series Chart.js (Allowed vs Mitigated) ---
            initChart() {
                const ctx = document.getElementById('trafficChart') as HTMLCanvasElement | null;
                if (!ctx) return;

                if (chartInstance && typeof chartInstance.destroy === 'function') {
                    chartInstance.destroy();
                }

                const useMbps = this.chartMode === 'mbps';

                chartInstance = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: [...chartLabels],
                        datasets: [
                            {
                                label: useMbps ? 'Allowed (Mbps)' : 'Allowed (PPS)',
                                data: useMbps ? [...passedMbpsHistory] : [...passedPpsHistory],
                                borderColor: '#06b6d4',
                                backgroundColor: 'rgba(6, 182, 212, 0.14)',
                                borderWidth: 2,
                                pointRadius: 0,
                                tension: 0.25,
                                fill: true
                            },
                            {
                                label: useMbps ? 'Dropped / Mitigated (Mbps)' : 'Dropped / Mitigated (PPS)',
                                data: useMbps ? [...droppedMbpsHistory] : [...droppedPpsHistory],
                                borderColor: '#ef4444',
                                backgroundColor: 'rgba(239, 68, 68, 0.18)',
                                borderWidth: 2,
                                pointRadius: 0,
                                tension: 0.25,
                                fill: true
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        animation: false,
                        interaction: {
                            mode: 'index',
                            intersect: false
                        },
                        plugins: {
                            legend: {
                                display: true,
                                position: 'top',
                                align: 'end',
                                labels: {
                                    color: '#9ca3af',
                                    boxWidth: 12,
                                    font: { size: 11 }
                                }
                            }
                        },
                        scales: {
                            x: {
                                grid: { display: false },
                                ticks: {
                                    color: '#6b7280',
                                    maxTicksLimit: 8,
                                    font: { size: 10 }
                                }
                            },
                            y: {
                                type: 'linear',
                                beginAtZero: true,
                                suggestedMax: useMbps ? 1 : 100,
                                grid: { color: '#1f2937' },
                                ticks: {
                                    color: '#9ca3af',
                                    font: { size: 10 }
                                }
                            }
                        }
                    }
                });
            },

            setChartMode(mode: 'pps' | 'mbps') {
                if (this.chartMode === mode) return;
                this.chartMode = mode;
                this.syncChartSeries();
            },

            syncChartSeries() {
                if (!chartInstance) return;
                const useMbps = this.chartMode === 'mbps';
                chartInstance.data.labels = [...chartLabels];
                chartInstance.data.datasets[0].label = useMbps ? 'Allowed (Mbps)' : 'Allowed (PPS)';
                chartInstance.data.datasets[0].data = useMbps ? [...passedMbpsHistory] : [...passedPpsHistory];
                chartInstance.data.datasets[1].label = useMbps ? 'Dropped / Mitigated (Mbps)' : 'Dropped / Mitigated (PPS)';
                chartInstance.data.datasets[1].data = useMbps ? [...droppedMbpsHistory] : [...droppedPpsHistory];
                const yScale = chartInstance.options.scales?.y as { suggestedMax?: number } | undefined;
                if (yScale) yScale.suggestedMax = useMbps ? 1 : 100;

                const canvas = chartInstance.canvas;
                if (!document.hidden && canvas.isConnected && canvas.offsetParent !== null) {
                    chartInstance.update('none');
                }
            },

            pushChartPoint(passedPps: number, droppedPps: number, passedBps: number, droppedBps: number, unixTs: number) {
                const dt = unixTs > 0 ? new Date(unixTs * 1000) : new Date();
                const label = dt.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

                chartLabels.push(label);
                passedPpsHistory.push(passedPps);
                droppedPpsHistory.push(droppedPps);
                passedMbpsHistory.push(Number((passedBps / 1_000_000).toFixed(3)));
                droppedMbpsHistory.push(Number((droppedBps / 1_000_000).toFixed(3)));

                if (chartLabels.length > HISTORY_POINTS) {
                    chartLabels.shift();
                    passedPpsHistory.shift();
                    droppedPpsHistory.shift();
                    passedMbpsHistory.shift();
                    droppedMbpsHistory.shift();
                }

                if (!chartInstance) {
                    this.initChart();
                } else {
                    this.syncChartSeries();
                }
            },

            // --- Formatting & Notification Helpers ---
            notify(message: string, type: 'success' | 'error' | 'info' = 'info') {
                const id = Date.now() + Math.floor(Math.random() * 1000);
                this.notifications.push({ id, message, type });
                if (this.notifications.length > 5) {
                    this.notifications.shift();
                }
                window.setTimeout(() => {
                    this.dismissNotification(id);
                }, 4500);
            },

            dismissNotification(id: number) {
                this.notifications = this.notifications.filter((n) => n.id !== id);
            },

            protoToName(proto: number): string {
                if (proto === 0) return 'ALL';
                if (proto === 6) return 'TCP';
                if (proto === 17) return 'UDP';
                if (proto === 1) return 'ICMP';
                if (proto === 58) return 'ICMPv6';
                return String(proto);
            },

            formatBytes(bytes: number): string {
                const val = Number(bytes) || 0;
                if (val <= 0) return '0 B';
                const k = 1024;
                const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
                const i = Math.min(sizes.length - 1, Math.floor(Math.log(val) / Math.log(k)));
                return `${parseFloat((val / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
            },

            formatBitsPerSec(bps: number): string {
                const val = Number(bps) || 0;
                if (val <= 0) return '0 bps';
                const k = 1000;
                const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
                const i = Math.min(sizes.length - 1, Math.floor(Math.log(val) / Math.log(k)));
                return `${parseFloat((val / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
            },

            formatNumber(n: number): string {
                return (Number(n) || 0).toLocaleString();
            },

            formatUptime(sec: number): string {
                const total = Math.max(0, Math.floor(Number(sec) || 0));
                const d = Math.floor(total / 86400);
                const h = Math.floor((total % 86400) / 3600);
                const m = Math.floor((total % 3600) / 60);
                const s = total % 60;
                if (d > 0) return `${d}d ${h}h ${m}m`;
                if (h > 0) return `${h}h ${m}m`;
                if (m > 0) return `${m}m ${s}s`;
                return `${s}s`;
            }
        };
    });
});

Alpine.start();
