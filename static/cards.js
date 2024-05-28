document.addEventListener('DOMContentLoaded', function() {
    const trueButton = document.getElementById('true-button');
    const falseButton = document.getElementById('false-button');
    const cardImage = document.getElementById('card-image');

    let gameOver = false; // Додаємо прапорець для перевірки завершення гри

    function displayCard(card) {
        if (card.message === 'No more cards') {
            window.location.href = '/home/cards/cards_over';
            gameOver = true; // Встановлюємо прапорець після завершення гри
        } else {
            cardImage.src = card.image;
        }
    }

    function sendUserAnswer(answer) {
        if (gameOver) return; // Перевіряємо прапорець перед надсиланням відповіді

        fetch('/home/cards', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrf_token // Додаємо CSRF-токен до заголовків
            },
            body: JSON.stringify({ user_answer: answer })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok ' + response.statusText);
            }
            return response.json();
        })
        .then(data => {
            console.log(data);
            if (data.message !== 'No more cards') {
                fetchNextCard();
            } else {
                gameOver = true;
                window.location.href = '/home/cards/cards_over';
            }
        })
        .catch(error => console.error('Error:', error));
    }

    function fetchNextCard() {
        if (gameOver) return; // Перевіряємо прапорець перед отриманням нової картки

        fetch('/home/cards', {
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrf_token // Додаємо CSRF-токен до заголовків
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok ' + response.statusText);
            }
            return response.json();
        })
        .then(data => displayCard(data))
        .catch(error => console.error('Error fetching next card:', error));
    }

    trueButton.addEventListener('click', () => sendUserAnswer(true));
    falseButton.addEventListener('click', () => sendUserAnswer(false));

    // Перший запит для отримання початкової картки
    fetchNextCard();
});
