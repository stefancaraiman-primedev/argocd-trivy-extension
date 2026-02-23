import axios from 'axios';

var vulnerabilityData = {}

/**
 * Fetch VulnerabilityReport by exact name (fails when Trivy uses hash for names > 63 chars).
 */
async function fetchReportByUrl(reportUrl) {
  const response = await axios.get(reportUrl)
    .catch(function () {
      return undefined;
    });
  return response;
}

/**
 * Find VulnerabilityReport by labels when direct fetch fails (e.g. hash-based names).
 * Uses Argo CD resource-tree to discover reports, then fetches each to match by labels.
 */
async function findReportByLabels(fallbackConfig) {
  if (!fallbackConfig?.appName) return undefined;

  const { appName, resourceNamespace, resourceKind, resourceName, containerName } = fallbackConfig;
  const treeUrl = `${window.location.origin}/api/v1/applications/${appName}/resource-tree`;
  const resourceUrl = `${window.location.origin}/api/v1/applications/${appName}/resource`;

  const treeResponse = await axios.get(treeUrl).catch(() => undefined);
  if (!treeResponse?.data?.nodes) return undefined;

  const workloadKind = (resourceKind || '').toLowerCase();

  const reportNodes = treeResponse.data.nodes.filter(
    (n) =>
      (n.kind === 'VulnerabilityReport' || n.kind === 'vulnerabilityreport') &&
      (n.group === 'aquasecurity.github.io' || !n.group) &&
      n.namespace === resourceNamespace &&
      Array.isArray(n.parentRefs) &&
      n.parentRefs.some(
        (p) =>
          (p.kind || '').toLowerCase() === workloadKind &&
          p.name === resourceName &&
          (p.namespace || '') === resourceNamespace
      )
  );

  for (const node of reportNodes) {
    const reportName = node.name;
    const fetchUrl = `${resourceUrl}?name=${encodeURIComponent(reportName)}&namespace=${encodeURIComponent(resourceNamespace)}&resourceName=${encodeURIComponent(reportName)}&version=v1alpha1&kind=VulnerabilityReport&group=aquasecurity.github.io`;
    const response = await axios.get(fetchUrl).catch(() => undefined);
    if (!response?.data?.manifest) continue;

    const manifest = JSON.parse(response.data.manifest);
    const labels = manifest?.metadata?.labels || {};
    const reportContainer = labels['trivy-operator.container.name'];

    if (!containerName || reportContainer === containerName) {
      return response;
    }
  }
  return undefined;
}

async function GetVulnerabilityData(reportUrl, fallbackConfig) {
  let response = await fetchReportByUrl(reportUrl);

  if (response === undefined && fallbackConfig) {
    response = await findReportByLabels(fallbackConfig);
  }

  if (response === undefined) {
    return [];
  }
  return JSON.parse(response?.data?.manifest).report.vulnerabilities;
}

export async function GridData(reportUrl, fallbackConfig) {
  const vulnData = await GetVulnerabilityData(reportUrl, fallbackConfig);

  const data = [];
  vulnData.forEach(v => data.push([
    v.resource,
    v.score,
    v.severity,
    v.fixedVersion,
    v.installedVersion,
    v.primaryLink,
    v.publishedDate,
    v.lastModifiedDate,
    v.title
  ]));

  return data
}

export async function DashboardData(reportUrl, fallbackConfig) {
  vulnerabilityData = await GetVulnerabilityData(reportUrl, fallbackConfig);

  if (vulnerabilityData.length === 0) {
    return {
      noVulnerabilityData: true
    }
  }

  return {
    severityData: severityCountData(),
    patchSummaryData: patchSummaryData(),
    topVulnerableResourcesData: topVulnerableResourcesData(15),
    vulnerabilityAgeDistribution: vulnerabilityAgeDistribution(),
    vulnerabilitiesByType: vulnerabilitiesByType(),
    noVulnerabilityData: false
  }
}

function severityCountData() {
  const data = [];
  [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "UNKNOWN"
  ].forEach(severity => {
    data.push({
      name: severity,
      count: vulnerabilityData.filter(d => d.severity === severity).length,
    })
  });
  return data;
}

function patchSummaryData() {
  const count = (severity, fixed = true) => {
    return vulnerabilityData.filter(v => (fixed ? v.fixedVersion !== "" : v.fixedVersion === "")
      && v.severity === severity).length
  }

  const data = []
  const severities = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "UNKNOWN"
  ]

  severities.forEach(severity => {
    data.push({
      severity: severity,
      fixed: count(severity),
      unfixed: count(severity, false)
    })
  })
  return data;
}

function topVulnerableResourcesData(size) {
  const data = []
  const resources = new Set()
  vulnerabilityData.forEach(v => { resources.add(v.resource) })

  const count = (resource, severity) => {
    return vulnerabilityData.filter(v => v.resource === resource && v.severity === severity).length
  }

  resources.forEach(resource => {
    data.push({
      name: resource,
      total: vulnerabilityData.filter(v => v.resource === resource).length,
      critical: count(resource, 'CRITICAL'),
      high: count(resource, 'HIGH'),
      medium: count(resource, 'MEDIUM'),
      low: count(resource, 'LOW')
    })
  })

  data.sort((a, b) => {
    return b.total - a.total
  })
  return data.slice(0, size - 1)
}

function vulnerabilityAgeDistribution() {
  const data = []

  const count = (severity, year) => {
    return vulnerabilityData.filter(v => {
      return v.severity === severity && new Date(v.publishedDate).getFullYear() === year
    }).length
  }

  let year = new Date().getFullYear() - 7
  while (year <= new Date().getFullYear()) {
    data.push({
      year: year,
      critical: count("CRITICAL", year),
      high: count("HIGH", year),
      medium: count("MEDIUM", year),
      low: count("LOW", year),
    })

    year++
  }
  return data
}

function vulnerabilitiesByType() {
  const vulnTypes = [
    "Overflow",
    "Memory corruption",
    "SQL injection",
    "XSS",
    "Directory traversal",
    "File inclusion",
    "CSRF",
    "XXE",
    "SSRF",
    "Open redirect",
    "Input validation",
    "DoS"
  ]

  const data = [];
  vulnTypes.forEach(vulnType => {

    data.push({
      name: vulnType,
      count: vulnerabilityData.filter(v => v.title.toLowerCase().includes(vulnType.toLowerCase())).length
    })
  })
  return data
}