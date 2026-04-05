let scanHistory = JSON.parse(localStorage.getItem("scanHistory")) || [];
let severityChart = null;
let serviceChart = null;
let cloudCredentials = JSON.parse(sessionStorage.getItem("cloudCredentials") || "null");

function showDashboard() {
    toggleSection("dashboard");
    loadDashboard();
}

function showHistory() {
    toggleSection("history");
    loadHistory();
}

function toggleSection(section) {
    const isDashboard = section === "dashboard";

    document.getElementById("dashboardSection").classList.toggle("hidden", !isDashboard);
    document.getElementById("historySection").classList.toggle("hidden", isDashboard);

    document.getElementById("navDashboard").classList.toggle("active", isDashboard);
    document.getElementById("navHistory").classList.toggle("active", !isDashboard);
    document.getElementById("mobileNavDashboard").classList.toggle("active", isDashboard);
    document.getElementById("mobileNavHistory").classList.toggle("active", !isDashboard);
}

async function triggerScan() {
    try {
        if (!cloudCredentials) {
            alert("Connect a cloud account before starting a scan.");
            openCloudModal();
            return;
        }

        setStatus("Scanning", "loading", true);

        const response = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ credentials: cloudCredentials })
        });

        if (!response.ok) {
            const errorPayload = await response.json().catch(() => ({}));
            throw new Error(errorPayload.detail || "Scan failed");
        }

        const data = await response.json();
        const cisScore = calculateCISScore(data.summary);

        updateHistory(data, cisScore);
        renderDashboard(data, cisScore);
        setStatus("Live", "live", false);
    } catch (error) {
        console.error(error);
        setStatus("Scan Failed", "error", false);
        alert(error.message || "Scan failed. Please try again.");
    }
}

function setStatus(text, variant, loading) {
    const loader = document.getElementById("loader");
    const indicator = document.getElementById("statusIndicator");

    loader.classList.toggle("hidden", !loading);
    indicator.className = `status-pill status-${variant}`;
    indicator.textContent = text;
}

function calculateCISScore(summary) {
    const penalty = (summary.CRITICAL * 10) + (summary.HIGH * 6) + (summary.MEDIUM * 3);
    return Math.max(0, 100 - penalty);
}

async function loadDashboard() {
    try {
        const response = await fetch("/report");
        if (!response.ok) {
            throw new Error("Report fetch failed");
        }

        const data = await response.json();
        const cisScore = calculateCISScore(data.summary);
        renderDashboard(data, cisScore);
        setStatus("Live", "live", false);
    } catch (error) {
        console.error(error);
        setStatus("Unavailable", "error", false);
    }
}

function renderDashboard(data, cisScore) {
    animateValue("risk", data.risk_score);
    animateValue("cisScore", cisScore);

    document.getElementById("total").textContent =
        data.summary.CRITICAL + data.summary.HIGH + data.summary.MEDIUM;

    document.getElementById("level").textContent = data.security_level || "-";
    document.getElementById("lastScan").textContent = formatTimestamp(data.scan_time);

    colorSecurityCard(data.security_level);
    updateCharts(data);
    updateCISBreakdown(data.summary);
    populateTable(data);
}

function colorSecurityCard(level) {
    const card = document.getElementById("securityCard");
    card.classList.remove("level-low", "level-moderate", "level-high");

    const map = {
        "LOW RISK": "level-low",
        "MODERATE RISK": "level-moderate",
        "HIGH RISK": "level-high"
    };

    if (map[level]) {
        card.classList.add(map[level]);
    }
}

function updateCharts(data) {
    if (severityChart) {
        severityChart.destroy();
    }

    if (serviceChart) {
        serviceChart.destroy();
    }

    severityChart = new Chart(document.getElementById("severityChart"), {
        type: "doughnut",
        data: {
            labels: ["Critical", "High", "Medium"],
            datasets: [{
                data: [data.summary.CRITICAL, data.summary.HIGH, data.summary.MEDIUM],
                backgroundColor: ["#d84b53", "#d97a18", "#3c78d8"],
                borderWidth: 0,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            cutout: "68%",
            plugins: {
                legend: {
                    position: "bottom",
                    labels: { usePointStyle: true, boxWidth: 10, padding: 18 }
                }
            }
        }
    });

    const serviceCounts = {};
    data.findings.forEach((finding) => {
        const key = `${finding.provider || ""} ${finding.service || "Unknown"}`.trim();
        serviceCounts[key] = (serviceCounts[key] || 0) + 1;
    });

    const labels = Object.keys(serviceCounts);
    const values = Object.values(serviceCounts);

    serviceChart = new Chart(document.getElementById("serviceChart"), {
        type: "bar",
        data: {
            labels,
            datasets: [{
                label: "Issues per service",
                data: values,
                borderRadius: 10,
                backgroundColor: "#1f8fff",
                maxBarThickness: 42
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: { grid: { display: false } },
                y: { beginAtZero: true, ticks: { precision: 0 } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function updateCISBreakdown(summary) {
    const container = document.getElementById("cisBreakdown");
    container.innerHTML = "";

    const controls = [
        { name: "Critical Findings", issues: summary.CRITICAL, weight: 12 },
        { name: "High Findings", issues: summary.HIGH, weight: 9 },
        { name: "Medium Findings", issues: summary.MEDIUM, weight: 6 }
    ];

    controls.forEach((control) => {
        const score = Math.max(0, 100 - (control.issues * control.weight));
        const tone = score >= 80 ? "#1e9e69" : score >= 55 ? "#d97a18" : "#d84b53";

        const wrapper = document.createElement("div");
        wrapper.className = "progress-wrapper";
        wrapper.innerHTML = `
            <div class="progress-meta">
                <div>
                    <strong>${control.name}</strong>
                    <div>${control.issues} issue${control.issues === 1 ? "" : "s"} influencing this area</div>
                </div>
                <strong>${score}%</strong>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width:${score}%; background:${tone};"></div>
            </div>
        `;
        container.appendChild(wrapper);
    });
}

function populateTable(data) {
    const severityFilter = document.getElementById("severityFilter").value;
    const searchText = document.getElementById("searchInput").value.trim().toLowerCase();
    const table = document.getElementById("findingsTable");

    table.innerHTML = "";

    const filtered = data.findings.filter((finding) => {
        const matchesSeverity = !severityFilter || finding.severity === severityFilter;
        const haystack = `${finding.provider || ""} ${finding.resource || ""} ${finding.issue || ""} ${finding.service || ""}`.toLowerCase();
        const matchesSearch = !searchText || haystack.includes(searchText);
        return matchesSeverity && matchesSearch;
    });

    if (!filtered.length) {
        table.innerHTML = `
            <tr class="empty-state">
                <td colspan="6">
                    <span class="empty-title">No findings match the current filters</span>
                    Try another severity level or a broader search term.
                </td>
            </tr>
        `;
        return;
    }

    const severityRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
    filtered
        .sort((a, b) => {
            const severityDiff = (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99);
            if (severityDiff !== 0) {
                return severityDiff;
            }
            return `${a.provider || ""} ${a.service || ""}`.localeCompare(`${b.provider || ""} ${b.service || ""}`);
        })
        .forEach((finding) => {
            const row = document.createElement("tr");
            row.innerHTML = `
                <td>${escapeHtml(`${finding.provider || ""} ${finding.service || "-"}`.trim())}</td>
                <td class="resource-cell"><span class="truncate" title="${escapeAttribute(finding.resource || "-")}">${escapeHtml(finding.resource || "-")}</span></td>
                <td class="issue-cell"><span class="truncate" title="${escapeAttribute(finding.issue || "-")}">${escapeHtml(finding.issue || "-")}</span></td>
                <td>${getSeverityBadge(finding.severity)}</td>
                <td>${escapeHtml(finding.region || "-")}</td>
                <td>
                    <button class="view-btn" type="button" data-recommendation="${encodeURIComponent(finding.recommendation || "No recommendation provided.")}">
                        View
                    </button>
                </td>
            `;
            table.appendChild(row);
        });
}

function getSeverityBadge(severity) {
    const variant = (severity || "").toLowerCase();
    return `<span class="severity-badge severity-${variant}">${escapeHtml(severity || "Unknown")}</span>`;
}

function updateHistory(data, cisScore) {
    scanHistory.unshift({
        time: data.scan_time,
        score: data.risk_score,
        cis: cisScore,
        level: data.security_level,
        provider: data.provider || "AWS"
    });

    scanHistory = scanHistory.slice(0, 10);
    localStorage.setItem("scanHistory", JSON.stringify(scanHistory));
    loadHistory();
}

function loadHistory() {
    const table = document.getElementById("historyTable");
    table.innerHTML = "";

    if (!scanHistory.length) {
        table.innerHTML = `
            <tr class="empty-state">
                <td colspan="4">
                    <span class="empty-title">No scan history yet</span>
                    Run a scan to start building a recent posture timeline.
                </td>
            </tr>
        `;
        return;
    }

    scanHistory.forEach((historyItem) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${formatTimestamp(historyItem.time)} (${escapeHtml(historyItem.provider || "AWS")})</td>
            <td>${historyItem.score}</td>
            <td>${historyItem.cis}</td>
            <td>${escapeHtml(historyItem.level || "-")}</td>
        `;
        table.appendChild(row);
    });
}

function animateValue(id, end, duration = 800) {
    const element = document.getElementById(id);
    const target = Number(end) || 0;
    const start = Number(element.textContent) || 0;
    const difference = target - start;
    let startTime = null;

    function step(currentTime) {
        if (!startTime) {
            startTime = currentTime;
        }

        const progress = Math.min((currentTime - startTime) / duration, 1);
        element.textContent = Math.round(start + (difference * progress));

        if (progress < 1) {
            requestAnimationFrame(step);
        }
    }
    requestAnimationFrame(step);
}

function showRecommendation(text) {
    if (!text) {
        return;
    }

    const modal = document.getElementById("recommendationModal");
    document.getElementById("modalText").textContent = text;
    modal.classList.add("show");
    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
}

function closeModal() {
    const modal = document.getElementById("recommendationModal");
    modal.classList.remove("show");
    modal.classList.add("hidden");
    modal.setAttribute("aria-hidden", "true");
}

function handleProviderChange() {
    const provider = document.getElementById("cloudProvider").value;
    document.getElementById("awsFields").classList.toggle("hidden", provider !== "AWS");
    document.getElementById("azureFields").classList.toggle("hidden", provider !== "AZURE");
    document.getElementById("gcpFields").classList.toggle("hidden", provider !== "GCP");
}

function openCloudModal() {
    const modal = document.getElementById("cloudModal");
    const message = document.getElementById("cloudAuthMessage");

    if (cloudCredentials) {
        document.getElementById("cloudProvider").value = cloudCredentials.provider || "AWS";
        document.getElementById("awsAccessKeyId").value = cloudCredentials.access_key_id || "";
        document.getElementById("awsSecretAccessKey").value = cloudCredentials.secret_access_key || "";
        document.getElementById("awsSessionToken").value = cloudCredentials.session_token || "";
        document.getElementById("awsDefaultRegion").value = cloudCredentials.default_region || "eu-north-1";
        document.getElementById("azureTenantId").value = cloudCredentials.tenant_id || "";
        document.getElementById("azureClientId").value = cloudCredentials.client_id || "";
        document.getElementById("azureClientSecret").value = cloudCredentials.client_secret || "";
        document.getElementById("azureSubscriptionId").value = cloudCredentials.subscription_id || "";
        document.getElementById("gcpProjectId").value = cloudCredentials.project_id || "";
        document.getElementById("gcpServiceAccountJson").value = cloudCredentials.service_account_json || "";
    }

    handleProviderChange();
    message.textContent = "";
    message.className = "cloud-auth-message";
    modal.classList.add("show");
    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
}

function closeCloudModal() {
    const modal = document.getElementById("cloudModal");
    modal.classList.remove("show");
    modal.classList.add("hidden");
    modal.setAttribute("aria-hidden", "true");
}

function setCloudConnectionStatus(text) {
    document.getElementById("cloudConnectionStatus").textContent = text;
}

async function saveCloudCredentials(event) {
    event.preventDefault();

    const provider = document.getElementById("cloudProvider").value;
    const message = document.getElementById("cloudAuthMessage");

    const payload = {
        credentials: {
            provider,
            access_key_id: document.getElementById("awsAccessKeyId").value.trim() || null,
            secret_access_key: document.getElementById("awsSecretAccessKey").value.trim() || null,
            session_token: document.getElementById("awsSessionToken").value.trim() || null,
            default_region: document.getElementById("awsDefaultRegion").value.trim() || "eu-north-1",
            tenant_id: document.getElementById("azureTenantId").value.trim() || null,
            client_id: document.getElementById("azureClientId").value.trim() || null,
            client_secret: document.getElementById("azureClientSecret").value.trim() || null,
            subscription_id: document.getElementById("azureSubscriptionId").value.trim() || null,
            project_id: document.getElementById("gcpProjectId").value.trim() || null,
            service_account_json: document.getElementById("gcpServiceAccountJson").value.trim() || null
        }
    };

    if (provider === "AWS" && (!payload.credentials.access_key_id || !payload.credentials.secret_access_key)) {
        message.textContent = "AWS access key and secret key are required.";
        message.className = "cloud-auth-message error";
        return;
    }
    if (provider === "AZURE" && (!payload.credentials.tenant_id || !payload.credentials.client_id || !payload.credentials.client_secret || !payload.credentials.subscription_id)) {
        message.textContent = "Azure tenant ID, client ID, client secret, and subscription ID are required.";
        message.className = "cloud-auth-message error";
        return;
    }
    if (provider === "GCP" && (!payload.credentials.project_id || !payload.credentials.service_account_json)) {
        message.textContent = "GCP project ID and service account JSON are required.";
        message.className = "cloud-auth-message error";
        return;
    }

    message.textContent = "Validating credentials...";
    message.className = "cloud-auth-message";

    try {
        const response = await fetch("/auth/cloud", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorPayload = await response.json().catch(() => ({}));
            throw new Error(errorPayload.detail || "Authentication failed");
        }

        const data = await response.json();
        cloudCredentials = payload.credentials;
        sessionStorage.setItem("cloudCredentials", JSON.stringify(cloudCredentials));

        message.textContent = `Connected to ${provider} account ${data.account_id || "-"}`;
        setCloudConnectionStatus(`Connected (${provider})`);
        message.className = "cloud-auth-message success";

        setTimeout(() => {
            closeCloudModal();
        }, 600);
    } catch (error) {
        console.error(error);
        message.textContent = error.message || "Authentication failed.";
        message.className = "cloud-auth-message error";
        setCloudConnectionStatus("Not connected");
    }
}

function formatTimestamp(value) {
    if (!value) {
        return "Waiting for data";
    }
    return new Date(value).toLocaleString();
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function escapeAttribute(value) {
    return escapeHtml(value).replaceAll("`", "&#96;");
}

document.getElementById("findingsTable").addEventListener("click", (event) => {
    if (event.target.classList.contains("view-btn")) {
        const text = decodeURIComponent(event.target.dataset.recommendation || "");
        showRecommendation(text);
    }
});

document.getElementById("recommendationModal").addEventListener("click", (event) => {
    if (event.target.id === "recommendationModal") {
        closeModal();
    }
});

document.getElementById("cloudModal").addEventListener("click", (event) => {
    if (event.target.id === "cloudModal") {
        closeCloudModal();
    }
});

document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
        closeModal();
        closeCloudModal();
    }
});

if (cloudCredentials?.provider) {
    setCloudConnectionStatus(`Connected (${cloudCredentials.provider})`);
}

loadHistory();
loadDashboard();
setInterval(loadDashboard, 30000);
