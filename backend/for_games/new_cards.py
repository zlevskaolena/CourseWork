from backend.config import app, db, Card


def load_image(file_path):
    with open(file_path, 'rb') as file:
        return file.read()


def create_card(image_path, correct_answer):
    with app.app_context():
        image_data = load_image(image_path)
        new_card = Card(image=image_data, correct_answer=correct_answer)
        db.session.add(new_card)
        db.session.commit()
        print("+ карточка")


if __name__ == "__main__":
    image_path = 'D:\\2024\\images_for_cards\\liberta.jpg'
    correct_answer = True
    create_card(image_path, correct_answer)


