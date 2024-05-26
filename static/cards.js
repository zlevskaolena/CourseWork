document.addEventListener('DOMContentLoaded', function() {
    const trueButton = document.getElementById('true-button');
    const falseButton = document.getElementById('false-button');
    const cardImage = document.getElementById('card-image');
    const cardWord = document.getElementById('card-word');

    function displayCard(card) {
        if (card.message === 'No more cards') {
            alert('No more cards available.');
            cardImage.src = '';
            cardWord.textContent = '';
        } else {
            cardImage.src = card.image;
            cardWord.textContent = card.word;
        }
    }

    function getNextCard() {
        fetch('/cards', {
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => displayCard(data))
        .catch(error => console.error('Error fetching next card:', error));
    }

    trueButton.addEventListener('click', getNextCard);
    falseButton.addEventListener('click', getNextCard);

    // Fetch the first card when the page loads
    getNextCard();
});
