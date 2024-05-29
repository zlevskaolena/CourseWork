document.addEventListener('DOMContentLoaded', function() {
    const trueButton = document.getElementById('true-button');
    const falseButton = document.getElementById('false-button');
    const cardImage = document.getElementById('card-image');
    function displayCard(card) {
        if (card.message === 'No more cards') {
            window.location.href = '/home/cards/cards_over';
        } else {
            cardImage.src = card.image;
        }
    }

    function sendUserAnswer(answer) {
        fetch('/home/cards', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrf_token
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
            fetchNextCard();
        })
        .catch(error => console.error('Error:', error));
    }

    function fetchNextCard() {
        fetch('/home/cards', {
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrf_token
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

    fetchNextCard();
});
