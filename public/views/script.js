// ======================== INICIALIZAÇÃO ========================
// Este bloco de código é executado quando o conteúdo da página está completamente carregado.
document.addEventListener('DOMContentLoaded', function() {
    // Funções iniciais para buscar dados e verificar autenticação
    fetchWeatherData();
    handleLoginForm();

    // Verificação de parâmetros da URL para exibir uma mensagem de logout
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('loggedOut') === 'true') {
        alert('Logout bem-sucedido!');
    }
});

// ======================== WIDGETS SCRIPTS ================================

// Funções de inicialização dos widgets
// (Você pode querer mover isso para o topo do arquivo ou para uma seção dedicada)


// ======================== BUSCA DE DADOS DE CLIMA ========================
// Função para buscar os dados de clima usando a geolocalização do navegador
function fetchWeatherData() {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(position => {
            const lat = position.coords.latitude;
            const lon = position.coords.longitude;
            fetch(`/weather-data?lat=${lat}&lon=${lon}`)
                .then(response => response.json())
                .then(data => {
                    const locationElement = document.getElementById('location');
                    const weatherElement = document.getElementById('weather');
                    if (locationElement && weatherElement && data.weather && data.weather.main) {
                        const temperatureKelvin = data.weather.main.temp;
                        const temperatureCelsius = (temperatureKelvin - 273.15).toFixed(2);
                        locationElement.innerHTML = `Localização: ${data.city}`;
                        weatherElement.innerHTML = `Clima: ${data.weather.weather[0].description}, Temperatura: ${temperatureCelsius} °C`;
                    }
                })
                .catch(err => {
                    console.error('Erro ao buscar dados meteorológicos:', err);
                });
        });
    } else {
        console.error('Geolocalização não é suportada por este navegador.');
    }
}

// ======================== MANIPULAÇÃO DO FORMULÁRIO DE LOGIN ========================
// Função para manipular submissões do formulário de login
function handleLoginForm() {
    const errorMessageElement = document.getElementById('error-message');
    if (errorMessageElement) {
        const errorMessageSpan = errorMessageElement.querySelector('.ErrorMessage');
        const loginForm = document.querySelector('form');
        loginForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const formData = new FormData(loginForm);
            fetch('/login', {
                method: 'POST',
                body: formData
            })
            .then(response => {
                if (response.status === 200) {
                    window.location.href = '/admin';
                } else {
                    return response.text();
                }
            })
            .then(text => {
                if (text) {
                    errorMessageSpan.textContent = text;
                    errorMessageElement.style.display = 'block';
                }
            })
            .catch(err => {
                console.error('Erro ao fazer login:', err);
            });
        });
    }
}

// ======================== VERIFICAÇÃO DE AUTENTICAÇÃO ========================
// Função para verificar o estado de autenticação do usuário
window.onload = function() {
    fetch('/check-auth')
        .then(response => response.json())
        .then(data => {
            if (data.isAuthenticated) {
                // Lógica para quando o usuário estiver autenticado
            } else {
                const errorMessage = document.getElementById('error-message');
                const queryString = window.location.search;
                const urlParams = new URLSearchParams(queryString);
                const error = urlParams.get('error');
                if (error) {
                    errorMessage.textContent = error;
                }
            }
        });
};
