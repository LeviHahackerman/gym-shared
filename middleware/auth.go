package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	UserIDKey contextKey = "userID"
	RoleKey   contextKey = "role"
)

type Claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func AuthMiddleware(jwtSecret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Извлекаем заголовок Authorization
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error": "Missing authorization token"}`, http.StatusUnauthorized)
				return
			}

			// 2. Проверяем формат заголовка (должен быть: Bearer <token>)
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, `{"error": "Invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]
			claims := &Claims{}

			// 3. Парсим и валидируем токен с помощью секретного ключа
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				// Проверяем метод подписи
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, errors.New("unexpected signing method")
				}
				return jwtSecret, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, `{"error": "Invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// 4. Извлекаем userID (sub) и роль
			userID, err := claims.GetSubject()
			if err != nil || userID == "" {
				http.Error(w, `{"error": "Invalid token subject"}`, http.StatusUnauthorized)
				return
			}

			// 5. Обогащаем контекст запроса данными пользователя
			ctx := context.WithValue(r.Context(), UserIDKey, userID)
			ctx = context.WithValue(ctx, RoleKey, claims.Role)

			// 6. Передаем управление следующему хэндлеру с новым контекстом
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
