const API_KEY = 'eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJkYTljY2JkNDViNmY1MTJjN2E0YWZmMzA5MjIxZDgyOCIsInN1YiI6IjYzZDBhM2M3NjZhZTRkMDA5ZTlkZjY4MSIsInNjb3BlcyI6WyJhcGlfcmVhZCJdLCJ2ZXJzaW9uIjoxfQ.N5j1M7YnwmMTjIWMdYQbdh5suW2hCDucbqlDgMku_UA';

let selectedContent = null;
let seasons = [];
let selectedSeason = 1;
let selectedEpisode = 1;
let bookmarks = { movies: [], tv: [] };
let recommendedMovies = [];
let recommendedSeries = [];

const mainContent = document.getElementById('main-content');

// Load data
async function loadData() {
  const stored = localStorage.getItem('streampal_bookmarks');
  if (stored) bookmarks = JSON.parse(stored);

  try {
    const res = await fetch('recommended.json');
    const data = await res.json();

    recommendedMovies = await Promise.all(
      data.movies.map(async (item) => await fetchItemDetails(item.id, 'movie'))
    );

    recommendedSeries = await Promise.all(
      data.series.map(async (item) => await fetchItemDetails(item.id, 'tv'))
    );
  } catch (err) {
    console.error('Failed to load recommended.json', err);
    recommendedMovies = [];
    recommendedSeries = [];
  }

  renderHome();
}
loadData();

async function fetchItemDetails(id, type) {
  const endpoint = type === 'tv' ? `tv/${id}` : `movie/${id}`;
  try {
    const res = await fetch(`https://api.themoviedb.org/3/${endpoint}?language=en-US`, {
      headers: { Authorization: `Bearer ${API_KEY}` }
    });
    if (!res.ok) throw new Error('Not found');
    const full = await res.json();
    return {
      id: full.id,
      title: full.title || full.name,
      poster_path: full.poster_path,
      media_type: type,
      overview: full.overview || 'No description available.',
      vote_average: full.vote_average
    };
  } catch (err) {
    console.warn(`Failed to load ${type} ID ${id}:`, err);
    return {
      id,
      title: `Unknown ${type === 'tv' ? 'Series' : 'Movie'} (ID ${id})`,
      poster_path: null,
      media_type: type,
      overview: 'Content not available.',
      vote_average: 0
    };
  }
}

document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const view = btn.dataset.view;
    if (view === 'home') renderHome();
    if (view === 'search') renderSearch();
    if (view === 'bookmarks') renderBookmarks();
    if (view === 'watch') renderWatch();
  });
});

// Global click handler
document.addEventListener('click', async e => {
  const card = e.target.closest('.content-card');
  if (card && card.dataset.id) {
    const id = parseInt(card.dataset.id);
    const type = card.dataset.type;
    await selectContent({ id, media_type: type });
  }

  if (e.target.closest('.bookmark-btn')) {
    e.stopPropagation();
    const card = e.target.closest('.content-card');
    if (card && card.dataset.id) {
      const id = parseInt(card.dataset.id);
      const type = card.dataset.type;
      toggleBookmark({ id, media_type: type });
    }
  }

  if (e.target.classList.contains('season-btn')) {
    selectedSeason = parseInt(e.target.dataset.season);
    selectedEpisode = 1;
    renderWatch();
  }

  if (e.target.classList.contains('episode-btn') && e.target.dataset.episode) {
    selectedEpisode = parseInt(e.target.dataset.episode);
    renderWatch();
  }
});

function renderHome() {
  mainContent.innerHTML = `
    <h1 class="brand-title">STREAMPAL</h1>
    <section class="section">
      <h2 class="section-title">Recommended Movies</h2>
      <div class="grid" id="movies-grid"></div>
    </section>
    <section class="section">
      <h2 class="section-title">Recommended Series</h2>
      <div class="grid" id="series-grid"></div>
    </section>
  `;
  renderRecommendedGrid('movies-grid', recommendedMovies);
  renderRecommendedGrid('series-grid', recommendedSeries);
}

function renderRecommendedGrid(containerId, items) {
  const container = document.getElementById(containerId);
  const shortDesc = (text) => text.length > 100 ? text.slice(0, 100) + '...' : text;

  container.innerHTML = items.map(item => `
    <div class="content-card" data-id="${item.id}" data-type="${item.media_type}">
      <div class="card-image">
        ${item.poster_path ? 
          `<img src="https://image.tmdb.org/t/p/w500${item.poster_path}" alt="${item.title}" class="card-img">` :
          `<div style="background:#374151;width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:#666;font-size:0.8rem;text-align:center;padding:1rem;">No Poster</div>`
        }
        <div class="card-overlay">
          <h3 class="card-title">${item.title}</h3>
          <div class="card-rating"><span>${item.vote_average?.toFixed(1) || 'N/A'}</span></div>
        </div>
      </div>
      <button class="bookmark-btn${isBookmarked(item) ? ' bookmarked' : ''}">★</button>
      <div class="card-short-description">
        <p>${shortDesc(item.overview)}</p>
      </div>
    </div>
  `).join('');
}

function renderSearch() {
  mainContent.innerHTML = `
    <h1 class="search-title">SEARCH</h1>
    <div class="search-container">
      <input type="text" id="search-input" class="search-input" placeholder="Search movies and TV shows...">
    </div>
    <div class="search-grid" id="search-grid"></div>
  `;
  document.getElementById('search-input').focus();
  document.getElementById('search-input').addEventListener('input', e => handleSearch(e.target.value));
}

async function handleSearch(query) {
  if (!query.trim()) {
    document.getElementById('search-grid').innerHTML = '';
    return;
  }

  try {
    const res = await fetch(`https://api.themoviedb.org/3/search/multi?query=${encodeURIComponent(query)}&language=en-US&page=1`, {
      headers: { Authorization: `Bearer ${API_KEY}` }
    });
    if (!res.ok) throw new Error('Search failed');
    const data = await res.json();

    // Filter out persons; include items even if poster is missing
    let results = data.results.filter(i => i.media_type === 'movie' || i.media_type === 'tv');

    // Optional: Prioritize more relevant/popular results if needed
    results.sort((a, b) => (b.vote_count || 0) - (a.vote_count || 0));

    const container = document.getElementById('search-grid');
    const shortDesc = (text) => text ? (text.length > 100 ? text.slice(0, 100) + '...' : text) : 'No description available.';

    container.innerHTML = results.map(item => `
      <div class="content-card" data-id="${item.id}" data-type="${item.media_type}">
        <div class="card-image">
          ${item.poster_path ? 
            `<img src="https://image.tmdb.org/t/p/w500${item.poster_path}" alt="${item.title || item.name}" class="card-img">` :
            `<div style="background:#374151;width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:#666;font-size:0.8rem;text-align:center;padding:1rem;">No Poster</div>`
          }
          <div class="card-overlay">
            <h3 class="card-title">${item.title || item.name}</h3>
            <div class="card-rating"><span>${item.vote_average?.toFixed(1) || 'N/A'}</span></div>
          </div>
        </div>
        <button class="bookmark-btn${isBookmarked({id: item.id, media_type: item.media_type}) ? ' bookmarked' : ''}">★</button>
        <div class="card-short-description">
          <p>${shortDesc(item.overview)}</p>
        </div>
      </div>
    `).join('');
  } catch (err) {
    console.error('Search error:', err);
    document.getElementById('search-grid').innerHTML = '<p style="text-align:center;color:#aaa;">Error performing search.</p>';
  }
}

function renderBookmarks() {
  const allIds = [
    ...bookmarks.movies.map(id => ({ id, media_type: 'movie' })),
    ...bookmarks.tv.map(id => ({ id, media_type: 'tv' }))
  ];

  if (allIds.length === 0) {
    mainContent.innerHTML = `<p style="text-align:center;padding:4rem;color:#aaa;">No bookmarks yet!</p>`;
    return;
  }

  mainContent.innerHTML = `
    <h1 class="brand-title">My Bookmarks</h1>
    <div class="grid" id="bookmarks-grid">Loading...</div>
  `;

  Promise.all(allIds.map(async ({ id, media_type }) => await fetchItemDetails(id, media_type)))
    .then(items => renderRecommendedGrid('bookmarks-grid', items));
}

async function selectContent({ id, media_type }) {
  const endpoint = media_type === 'tv' ? `tv/${id}` : `movie/${id}`;
  try {
    const res = await fetch(`https://api.themoviedb.org/3/${endpoint}?language=en-US`, {
      headers: { Authorization: `Bearer ${API_KEY}` }
    });
    if (!res.ok) throw new Error('Not found');
    selectedContent = await res.json();
    selectedContent.media_type = media_type;

    if (media_type === 'tv') {
      await fetchSeasons(id);
      selectedSeason = seasons.length > 0 ? seasons[0].season_number : 1;
      selectedEpisode = 1;
    }

    renderWatch();
    document.querySelector('[data-view="watch"]').click();
  } catch (err) {
    console.error('Error selecting content:', err);
  }
}

async function fetchSeasons(tvId) {
  try {
    const res = await fetch(`https://api.themoviedb.org/3/tv/${tvId}?language=en-US`, {
      headers: { Authorization: `Bearer ${API_KEY}` }
    });
    const data = await res.json();
    seasons = data.seasons.filter(s => s.season_number > 0 && s.episode_count > 0);
  } catch (err) {
    console.error('Error fetching seasons:', err);
    seasons = [];
  }
}

function renderWatch() {
  if (!selectedContent) {
    mainContent.innerHTML = `
    <p> Best results without VPN </p>
    <div class="player-container"><p style="text-align:center;padding:4rem;color:#fff;">No content selected.</p></div>`;
    return;
  }

  const isTV = selectedContent.media_type === 'tv';
  const streamUrl = isTV 
    ? `https://v2.vidsrc.me/embed/${selectedContent.id}/${selectedSeason}-${selectedEpisode}/`
    : `https://v2.vidsrc.me/embed/${selectedContent.id}/`;

  mainContent.innerHTML = `
    <button class="back-btn" onclick="document.querySelector('[data-view=home]').click()">← Back</button>
    <div class="player-container">
      <iframe class="player" src="${streamUrl}" allowfullscreen></iframe>
    </div>
    <h2 class="content-title">${selectedContent.title || selectedContent.name}</h2>

    ${isTV && seasons.length > 0 ? `
      <div class="controls-section">
        <div class="control-panel">
          <h3 class="control-title">Seasons</h3>
          <div class="button-group">
            ${seasons.map(s => `
              <button class="episode-btn season-btn${selectedSeason === s.season_number ? ' active' : ''}" 
                      data-season="${s.season_number}">
                Season ${s.season_number}
              </button>
            `).join('')}
          </div>
        </div>
        <div class="control-panel">
          <h3 class="control-title">Episodes (Season ${selectedSeason})</h3>
          <div class="episode-grid">
            ${Array.from({length: seasons.find(s => s.season_number === selectedSeason)?.episode_count || 0}, (_, i) => i+1)
              .map(ep => `
                <button class="episode-btn${selectedEpisode === ep ? ' active' : ''}" data-episode="${ep}">
                  ${ep}
                </button>
              `).join('')}
          </div>
        </div>
      </div>
    ` : (isTV ? `<p style="color:#aaa;text-align:center;margin:2rem 0;">No seasons available.</p>` : '')}

    ${selectedContent.overview ? `
      <div class="description">
        <h3>Description</h3>
        <p>${selectedContent.overview}</p>
      </div>
    ` : ''}
  `;
}

function toggleBookmark(item) {
  const type = item.media_type === 'tv' ? 'tv' : 'movies';
  const arr = bookmarks[type];
  const index = arr.indexOf(item.id);
  if (index > -1) arr.splice(index, 1);
  else arr.push(item.id);

  localStorage.setItem('streampal_bookmarks', JSON.stringify(bookmarks));

  const active = document.querySelector('.nav-btn.active');
  if (active) active.click();
}

function isBookmarked(item) {
  const type = item.media_type === 'tv' ? 'tv' : 'movies';
  return bookmarks[type].includes(item.id);
}

document.querySelector('[data-view="home"]').click();