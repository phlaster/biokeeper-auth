-- 03_permission.sql

CREATE TABLE permission (
    id SERIAL PRIMARY KEY,
    value INT NOT NULL DEFAULT -1,
    info TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION calculate_permission_value()
RETURNS TRIGGER AS $$
BEGIN
    NEW.value = POWER(2, NEW.id - 1); -- Вычисляем value на основе id
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER calculate_permission_trigger
BEFORE INSERT ON permission
FOR EACH ROW
EXECUTE FUNCTION calculate_permission_value();


INSERT INTO permission (info) VALUES
    ('Назначение администраторов'),
    ('Редактирование паролей'),
    ('Редактирование товаров'),
    ('Просмотр статистики');

