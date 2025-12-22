async function searchTmdbMulti(query) {
    const accessToken = 'eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJkYTljY2JkNDViNmY1MTJjN2E0YWZmMzA5MjIxZDgyOCIsInN1YiI6IjYzZDBhM2M3NjZhZTRkMDA5ZTlkZjY4MSIsInNjb3BlcyI6WyJhcGlfcmVhZCJdLCJ2ZXJzaW9uIjoxfQ.N5j1M7YnwmMTjIWMdYQbdh5suW2hCDucbqlDgMku_UA';  // Your Read Access Token
    const baseUrl = 'https://api.themoviedb.org/3/search/multi';
    const url = `${baseUrl}?query=${encodeURIComponent(query)}`;

    try {
        const response = await fetch(url, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const data = await response.json();

        // Extract relevant entries (movies and TV shows only)
        const entries = data.results
            .filter(item => item.media_type === 'movie' || item.media_type === 'tv')
            .map(item => ({
                id: item.id,
                title: item.media_type === 'movie' ? item.title : item.name,
                media_type: item.media_type
            }));

        console.log(entries);
        return entries;
    } catch (error) {
        console.error('Error fetching data:', error);
        return [];
    }
}

// Example usage
searchTmdbMulti('rick and morty');