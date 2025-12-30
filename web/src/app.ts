import Alpine from 'alpinejs';
import Chart from 'chart.js/auto';

// Simple WebSocket Client
class WSClient {
    private ws: WebSocket | null = null;
    private url: string;
    private reconnectInterval: number = 3000;

    constructor(port: number) {
        // Assume WS on same host, different port for now (8182) as configured
        this.url = `ws://${window.location.hostname}:8182`;
        this.connect();
    }

    connect() {
        this.ws = new WebSocket(this.url, "lws-cyrenus-protocol");

        this.ws.onopen = () => {
            console.log('WS Connected');
        };

        this.ws.onmessage = (event) => {
            try {
                const payload = JSON.parse(event.data);
                this.handleMessage(payload);
            } catch (e) {
                console.error('Invalid JSON', e);
            }
        };

        this.ws.onclose = () => {
            console.log('WS Disconnected, retrying...');
            setTimeout(() => this.connect(), this.reconnectInterval);
        };
    }

    handleMessage(msg: any) {
        // Dispatch custom event for Alpine to catch
        window.dispatchEvent(new CustomEvent('ws-message', { detail: msg }));
    }
}

// Initialize Global State
const ws = new WSClient(8182);

document.addEventListener('alpine:init', () => {
    Alpine.data('dashboard_data', () => {
        // Use a local variable for the chart instance to avoid Alpine proxying it
        let chartInstance: any = null;

        return {
            stats: {
                pps: 0,
                attacks: 0
            },
            traffic: [] as any[],
            attacks: [] as any[],
            rules: [] as any[],
            apiKeys: [] as any[],
            notifications: [] as any[],
            security: {
                events: [] as any[],
                stats: {
                    total_events: 0,
                    critical_alerts: 0,
                    events_blocked: 0,
                    tetragon_running: false
                },
                policies: [] as any[],
                logs: [] as any[],
                config: '',
                filters: {
                    severity: '',
                    eventType: '',
                    limit: 50
                },
                currentPolicy: { name: '', content: '' },
                showModal: false
            },

            // UI State
            trafficPage: 1,
            itemsPerPage: 10,
            sponsorshipModalOpen: false,

            newApiKey: { name: '', permissions: 'read,write', expires_in_days: 0 },
            generatedKey: null as string | null,
            settings: {
                interface: 'loading...',
                log_level: 0,
                geoip_enabled: false
            },
            newRule: {
                ip: '',
                port: 0,
                proto: 'tcp',
                action: 'drop'
            },

            init() {
                console.log('Dashboard Data Init');

                // Proactive auth check
                if (!localStorage.getItem('token')) {
                    window.location.href = '/login.html';
                    return;
                }

                this.initChart();

                // Fetch initial data
                this.fetchTraffic();
                this.fetchAttacks();
                this.fetchRules();
                this.fetchSettings();

                // Listen for WS updates
                window.addEventListener('ws-message', (e: any) => {
                    const msg = (e as CustomEvent).detail;
                    if (msg.type === 'traffic_update' && msg.data) {
                        const pps = Number(msg.data.pps) || 0;
                        this.stats.pps = pps;
                        this.updateChart(pps);
                    }
                    if (msg.type === 'security_update') {
                        // Silent update for low-severity events
                        this.fetchSecurityEvents();
                        this.fetchSecurityStats();
                    }
                    if (msg.type === 'security_alert') {
                        this.notify(`Security Alert: ${msg.message}`, 'error');
                        this.fetchSecurityStats();
                        this.fetchSecurityEvents(); // Also refresh list for high severity
                    }
                });
            },

            async fetchTraffic() {
                try {
                    const res = await fetch('/api/v1/traffic/stats', {
                        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
                    });
                    if (res.status === 401) window.location.href = '/login.html';
                    const data = await res.json();
                    this.traffic = Array.isArray(data) ? data : [];
                } catch (e) {
                    console.error('Fetch traffic failed', e);
                    this.traffic = [];
                }
            },

            async fetchAttacks() {
                try {
                    const res = await fetch('/api/v1/attacks', {
                        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
                    });
                    if (res.status === 401) window.location.href = '/login.html';
                    this.attacks = await res.json();
                    this.stats.attacks = this.attacks.length;
                } catch (e) {
                    console.error('Fetch attacks failed', e);
                }
            },

            async fetchRules() {
                try {
                    const res = await fetch('/api/v1/rules', {
                        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
                    });
                    if (res.status === 401) window.location.href = '/login.html';
                    this.rules = await res.json();
                } catch (e) {
                    console.error('Fetch rules failed', e);
                }
            },

            async fetchSettings() {
                try {
                    const res = await fetch('/api/v1/system/settings', {
                        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
                    });
                    if (res.status === 401) window.location.href = '/login.html';
                    this.settings = await res.json();
                } catch (e) {
                    console.error('Fetch settings failed', e);
                }
            },

            async fetchApiKeys() {
                try {
                    const res = await fetch('/api/v1/keys', {
                        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
                    });
                    if (res.status === 401) window.location.href = '/login.html';
                    this.apiKeys = await res.json();
                } catch (e) {
                    console.error('Fetch keys failed', e);
                }
            },

            async createApiKey() {
                try {
                    const res = await fetch('/api/v1/keys', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${localStorage.getItem('token')}`
                        },
                        body: JSON.stringify(this.newApiKey)
                    });
                    if (res.ok) {
                        const data = await res.json();
                        this.generatedKey = data.api_key;
                        this.fetchApiKeys();
                        this.newApiKey = { name: '', permissions: 'read,write', expires_in_days: 0 };
                    }
                } catch (e) {
                    console.error('Create key failed', e);
                }
            },

            async deleteApiKey(id: number) {
                if (!confirm('Are you sure? This cannot be undone.')) return;
                try {
                    const res = await fetch('/api/v1/keys', {
                        method: 'DELETE',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${localStorage.getItem('token')}`
                        },
                        body: JSON.stringify({ id })
                    });
                    if (res.ok) this.fetchApiKeys();
                } catch (e) {
                    console.error('Delete key failed', e);
                }
            },

            async addRule() {
                try {
                    const res = await fetch('/api/v1/rules', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${localStorage.getItem('token')}`
                        },
                        body: JSON.stringify(this.newRule)
                    });
                    if (res.ok) {
                        this.fetchRules();
                        this.notify('Rule added successfully', 'success');
                        this.newRule = { ip: '', port: 0, proto: 'tcp', action: 'drop' };
                    }
                } catch (e) {
                    console.error('Add rule failed', e);
                }
            },

            async deleteRule(rule: any) {
                try {
                    const protoMap: any = { 'TCP': 6, 'UDP': 17, 'ICMP': 1 };
                    const id = `${rule.ip}_${rule.port}_${protoMap[rule.proto] || 6}`;
                    const res = await fetch(`/api/v1/rules/${id}`, {
                        method: 'DELETE',
                        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
                    });
                    if (res.ok) {
                        this.fetchRules();
                        this.notify('Rule deleted successfully', 'success');
                    }
                } catch (e) {
                    console.error('Delete rule failed', e);
                }
            },

            async blockIP(ip: string) {
                // Determine proto? Default to all? 
                // For simplified "Block IP", we might just add a rule for this IP (any port/proto? Rule structure requires port/proto).
                // Let's assume blocking all traffic from this IP.
                // But our backend rule engine is tuple based (IP:Port:Proto).
                // Port 0 is now a wildcard (matches any port)
                // Block both TCP and UDP to cover all traffic

                const token = localStorage.getItem('token');
                if (!token) {
                    this.notify('Not authenticated', 'error');
                    return;
                }

                try {
                    // Block TCP traffic
                    const tcpRule = {
                        ip: ip,
                        port: 0,  // Wildcard - matches all ports
                        proto: 'tcp',
                        action: 'drop'
                    };

                    await fetch('/api/v1/rules', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        },
                        body: JSON.stringify(tcpRule)
                    });

                    // Block UDP traffic
                    const udpRule = {
                        ip: ip,
                        port: 0,  // Wildcard - matches all ports
                        proto: 'udp',
                        action: 'drop'
                    };

                    await fetch('/api/v1/rules', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        },
                        body: JSON.stringify(udpRule)
                    });

                    // Refresh rules list
                    await this.fetchRules();
                    this.notify(`Blocked ${ip} (all ports, TCP+UDP)`, 'success');
                } catch (error) {
                    console.error('Error blocking IP:', error);
                    this.notify(`Failed to block ${ip}`, 'error');
                }
            },

            formatBytes(bytes: number) {
                if (bytes === 0) return '0 B';
                const k = 1024;
                const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            },

            initChart() {
                const ctx = document.getElementById('trafficChart') as HTMLCanvasElement;
                if (!ctx) {
                    console.warn('[Chart] Canvas not found');
                    return;
                }

                // Cleanup existing instance
                if (chartInstance && typeof chartInstance.destroy === 'function') {
                    chartInstance.destroy();
                }

                try {
                    chartInstance = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: Array(30).fill(''),
                            datasets: [{
                                label: 'PPS',
                                data: Array(30).fill(0),
                                borderColor: '#06b6d4',
                                borderWidth: 2,
                                pointRadius: 0,
                                tension: 0.1,
                                fill: true,
                                backgroundColor: 'rgba(6, 182, 212, 0.1)'
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            animation: false,
                            plugins: {
                                legend: { display: false }
                            },
                            scales: {
                                x: { display: false },
                                y: {
                                    type: 'linear',
                                    beginAtZero: true,
                                    suggestedMax: 100,
                                    grid: { color: '#1f2937' },
                                    ticks: {
                                        color: '#9ca3af',
                                        font: { size: 10 }
                                    }
                                }
                            }
                        }
                    });
                    console.log('[Chart] Initialized');
                } catch (e) {
                    console.error('[Chart] Init failed', e);
                }
            },

            updateChart(value: number) {
                // Lazy search if chart not initialized
                if (!chartInstance) {
                    this.initChart();
                }

                // If still not initialized (e.g. canvas missing), just return
                if (!chartInstance) return;

                try {
                    // 1. Always update the data model to preserve history
                    const dataset = chartInstance.data.datasets[0];
                    if (dataset && Array.isArray(dataset.data)) {
                        dataset.data.push(value);
                        if (dataset.data.length > 30) {
                            dataset.data.shift();
                        }
                    }

                    if (chartInstance.data.labels && Array.isArray(chartInstance.data.labels)) {
                        chartInstance.data.labels.push('');
                        if (chartInstance.data.labels.length > 30) {
                            chartInstance.data.labels.shift();
                        }
                    }

                    // 2. Check for visibility before rendering to prevent errors and save resources
                    const canvas = chartInstance.canvas;
                    if (document.hidden || !canvas.isConnected || canvas.offsetParent === null) {
                        return;
                    }

                    // 3. Render
                    chartInstance.update('none');
                } catch (e) {
                    console.error('[Chart] Update failed', e);
                    // CRITICAL: Do NOT destroy/re-init here to prevent stack overflow/infinite loops
                }
            }
            ,

            // --- Helpers ---
            notify(message: string, type: 'success' | 'error' | 'info' = 'info') {
                const id = Date.now();
                this.notifications.push({ id, message, type });
                setTimeout(() => {
                    this.notifications = this.notifications.filter((n: any) => n.id !== id);
                }, 3000);
            },

            get paginatedTraffic() {
                const start = (this.trafficPage - 1) * this.itemsPerPage;
                const end = start + this.itemsPerPage;
                return this.traffic.slice(start, end);
            },

            totalPages() {
                return Math.ceil(this.traffic.length / this.itemsPerPage);
            },

            nextPage() {
                if (this.trafficPage < this.totalPages()) this.trafficPage++;
            },

            prevPage() {
                if (this.trafficPage > 1) this.trafficPage--;
            },

            // --- Security Methods ---
            async fetchSecurityStats() {
                try {
                    const res = await fetch('/api/v1/security/stats', {
                        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
                    });
                    this.security.stats = await res.json();
                } catch (e) { console.error('Stats failed', e); }
            },

            async fetchSecurityEvents() {
                try {
                    let url = `/api/v1/security/events?limit=${this.security.filters.limit}`;
                    if (this.security.filters.severity) url += `&severity=${this.security.filters.severity}`;
                    if (this.security.filters.eventType) url += `&event_type=${this.security.filters.eventType}`;

                    const res = await fetch(url, {
                        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
                    });
                    const data = await res.json();
                    this.security.events = data.events || [];
                } catch (e) { console.error('Events failed', e); }
            },

            async fetchSecurityPolicies() {
                try {
                    const res = await fetch('/api/v1/security/policies', {
                        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
                    });
                    const data = await res.json();
                    this.security.policies = data.policies || [];
                } catch (e) { console.error('Policies failed', e); }
            },

            async deployPolicy(name: string) {
                try {
                    const res = await fetch(`/api/v1/security/policy/${name}/deploy`, {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
                    });
                    if (res.ok) {
                        this.notify('Policy deployed successfully', 'success');
                        this.fetchSecurityPolicies();
                    }
                } catch (e) { this.notify('Deployment failed', 'error'); }
            },

            async savePolicy() {
                try {
                    const res = await fetch(`/api/v1/security/policy/${this.security.currentPolicy.name}`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${localStorage.getItem('token')}`
                        },
                        body: JSON.stringify({ content: this.security.currentPolicy.content })
                    });
                    if (res.ok) {
                        this.notify('Policy saved', 'success');
                        this.security.showModal = false;
                        this.fetchSecurityPolicies();
                    }
                } catch (e) { this.notify('Save failed', 'error'); }
            }
        };
    });
});

Alpine.start();
