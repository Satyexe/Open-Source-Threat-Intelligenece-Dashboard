document.addEventListener('DOMContentLoaded', function () {
  const input = document.getElementById('search-input');
  const iocInput = document.getElementById('iocSearch'); // IOC search box
  const iocDatalist = document.getElementById('iocTypes'); // Datalist for IOC suggestions

  // 🔍 General feed search
  input.addEventListener('input', function (e) {
    const q = e.target.value.toLowerCase();
    const rows = document.querySelectorAll('.feed-row');
    rows.forEach(r => {
      const text = r.innerText.toLowerCase();
      r.style.display = text.includes(q) ? '' : 'none';
    });
    document.getElementById('total-count').innerText =
      document.querySelectorAll('.feed-row:not([style*="display: none"])').length;
  });

  // 📡 Fetch advisories & build source counts + IOC suggestions
  fetch('/api/advisories')
    .then(r => r.json())
    .then(data => {
      const counts = {};
      const iocSet = new Set();

      data.forEach(d => {
        counts[d.source] = (counts[d.source] || 0) + 1;

        // Extract IOC values from API response (if present)
        if (d.iocs && Array.isArray(d.iocs)) {
          d.iocs.forEach(ioc => iocSet.add(ioc.trim()));
        }
      });

      // Fill sources list
      const sourcesList = document.getElementById('sources-list');
      for (const k in counts) {
        const li = document.createElement('li');
        li.textContent = k + ': ' + counts[k];
        sourcesList.appendChild(li);
      }
      document.getElementById('total-count').innerText = data.length;

      // Fill IOC datalist suggestions automatically
      iocDatalist.innerHTML = '';
      iocSet.forEach(ioc => {
        const option = document.createElement('option');
        option.value = ioc;
        iocDatalist.appendChild(option);
      });
    })
    .catch(e => console.log('api/advisories error', e));

  // 🎯 IOC live filter
  if (iocInput) {
    iocInput.addEventListener('input', function () {
      const query = this.value.toLowerCase();
      const rows = document.querySelectorAll('.feed-row');

      rows.forEach(r => {
        const iocData = (r.dataset.iocs || '').toLowerCase();
        const rowText = r.innerText.toLowerCase();
        r.style.display = (iocData.includes(query) || rowText.includes(query)) ? '' : 'none';
      });
    });
  }

  // 📌 Feed row modal open
  document.querySelectorAll('.feed-row').forEach(r => {
    r.addEventListener('click', () => {
      const modal = document.getElementById('detail-modal');
      document.getElementById('modal-title').innerText = r.dataset.title;
      document.getElementById('modal-source').innerText = r.dataset.source;
      document.getElementById('modal-desc').innerText = r.dataset.desc;
      document.getElementById('modal-iocs').innerText = 'IOCs: ' + (r.dataset.iocs || 'none');
      modal.style.display = 'flex';
    });
  });

  // ❌ Modal close
  const close = document.getElementById('modal-close');
  if (close) close.addEventListener('click', () => document.getElementById('detail-modal').style.display = 'none');

  // 📂 Sidebar toggle
  const sidebarToggle = document.getElementById('sidebar-toggle');
  const sidebar = document.getElementById('sidebar');

  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', (e) => {
      e.stopPropagation();
      sidebar.classList.toggle('collapsed');
    });

    // Collapse sidebar when clicking outside
    document.addEventListener('click', (e) => {
      const isClickInside = sidebar.contains(e.target) || sidebarToggle.contains(e.target);
      if (!isClickInside && !sidebar.classList.contains('collapsed')) {
        sidebar.classList.add('collapsed');
      }
    });
  }

  // Auto-expand sidebar when clicking a nav item
  document.querySelectorAll('#sidebar nav a').forEach(link => {
    link.addEventListener('click', () => {
      if (sidebar.classList.contains('collapsed')) {
        sidebar.classList.remove('collapsed');
      }
    });
  });
});

// Click-to-filter from CVSS Bar Chart
document.getElementById('cvssBar').onclick = function(evt) {
  const points = cvssChart.getElementsAtEventForMode(evt, 'nearest', { intersect: true }, true);
  if (points.length) {
    const label = cvssChart.data.labels[points[0].index];
    const rows = document.querySelectorAll('.feed-row');
    rows.forEach(r => {
      const sev = r.querySelector('.col-sev')?.innerText || '';
      r.style.display = sev.includes(label) ? '' : 'none';
    });
  }
};
