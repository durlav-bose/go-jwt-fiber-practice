package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	jwtware "github.com/gofiber/jwt/v3"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Repository struct {
	DB *gorm.DB
}

type SignupRequest struct {
	Name     string
	Email    string
	Password string
}

type Persons struct {
	ID       uint   `gorm:"primary key;autoIncrement" json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string
	Password string
}

type Config struct {
	Host     string
	Port     string
	Password string
	User     string
	DBName   string
	SSLMode  string
}

var SECRET = []byte("super-secret-auth-key")

func CreateJwtToken(person *Persons) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	fmt.Println("person", person)
	fmt.Println("claims", claims)
	claims["used_id"] = person.ID
	fmt.Println("claims", claims)

	tokenstr, err := token.SignedString(SECRET)
	if err != nil {
		fmt.Println("error from create jwt: ", err)
		return "", err
	}
	fmt.Println("tokenstr", tokenstr)
	return tokenstr, nil
}

func (r *Repository) Signup(context *fiber.Ctx) error {
	req := new(SignupRequest)
	if err := context.BodyParser(&req); err != nil {
		return err
	}
	if req.Email == "" || req.Name == "" || req.Password == "" {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid signup credentials")
	}
	hash, errr := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if errr != nil {
		return errr
	}
	user := &Persons{
		Name:     req.Name,
		Email:    req.Email,
		Password: string(hash),
	}
	errrr := r.DB.Create(user).Error
	if errrr != nil {
		context.Status(http.StatusBadRequest).JSON(&fiber.Map{"message": "Could not create person"})
		return errr
	}

	fmt.Println(user)
	token, err := CreateJwtToken(&Persons{
		Name:     req.Name,
		Email:    req.Email,
		Password: string(hash),
	})
	if err != nil {
		return err
	}

	return context.JSON(fiber.Map{"token": token, "user": user})
}

func (r *Repository) Login(context *fiber.Ctx) error {
	req := new(LoginRequest)
	if err := context.BodyParser(req); err != nil {
		return err
	}

	if req.Email == "" || req.Password == "" {
		return fiber.NewError(fiber.StatusBadRequest, "invalid login credentials")
	}

	fmt.Println("req", req)

	user := &Persons{
		Email:    req.Email,
		Password: req.Password,
	}
	fmt.Println("user", user)
	errrrr := r.DB.Where("email = ?", req.Email).Find(&user)

	if errrrr != nil {
		fmt.Println("errrrr", errrrr)
		return errrrr.Error
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return err
	}

	token, err := CreateJwtToken(user)
	if err != nil {
		fmt.Println("creat token call login error", err)
		return err
	}

	return context.JSON(fiber.Map{"token": token, "user": user})
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("env file not loaded")
	}

	config := &Config{
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
		Password: os.Getenv("DB_PASS"),
		User:     os.Getenv("DB_USER"),
		DBName:   os.Getenv("DB_DBNAME"),
		SSLMode:  os.Getenv("DB_SSLMODE"),
	}

	dsn := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=%s password=%s port=%s", config.Host, config.User, config.DBName, config.SSLMode, config.Password, config.Port)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		panic(err)
	}

	errr := db.AutoMigrate(&Persons{})

	if errr != nil {
		log.Fatal("Can not migrate db")
	}

	r := &Repository{
		DB: db,
	}

	app := fiber.New()
	app.Post("/signup", r.Signup)
	app.Post("/login", r.Login)
	private := app.Group("/private")
	private.Use(jwtware.New(jwtware.Config{
		SigningKey: SECRET,
	}))
	private.Get("/", func(c *fiber.Ctx) error {

		return c.JSON(fiber.Map{"success": true, "path": "private"})
	})

	public := app.Group("/public")
	public.Get("/", func(c *fiber.Ctx) error {

		return c.JSON(fiber.Map{"success": true, "path": "public"})
	})

	if err := app.Listen(":4000"); err != nil {
		panic(err)
	}
}
