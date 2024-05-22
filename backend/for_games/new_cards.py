from backend.config import app, db, Card



def load_image(file_path):
    with open(file_path, 'rb') as file:
        return file.read()


def create_card(image_path, word, correct_answer):
    with app.app_context():
        image_data = load_image(image_path)
        new_card = Card(image=image_data, word=word, correct_answer=correct_answer)
        db.session.add(new_card)
        db.session.commit()
        print("Card created successfully!")


if __name__ == "__main__":
    image_path = 'D:\\2024\\images_for_cards\\Dio.jpg'
    word = 'Dio'
    correct_answer = True
    create_card(image_path, word, correct_answer)


