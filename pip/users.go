package pip

type UserAttributes struct {
	ID      string
	Name    string
	Email   string
	Roles   []string
	Picture string
}

var Users = map[string]UserAttributes{
	"CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs": {
		ID:      "rick@the-citadel.com",
		Name:    "Rick Sanchez",
		Email:   "rick@the-citadel.com",
		Roles:   []string{"admin", "evil_genius"},
		Picture: "https://www.topaz.sh/assets/templates/citadel/img/Rick%20Sanchez.jpg",
	},
	"CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs": {
		ID:      "beth@the-smiths.com",
		Name:    "Beth Smith",
		Email:   "beth@the-smiths.com",
		Roles:   []string{"viewer"},
		Picture: "https://www.topaz.sh/assets/templates/citadel/img/Beth%20Smith.jpg",
	},
	"CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs": {
		ID:      "morty@the-citadel.com",
		Name:    "Morty Smith",
		Email:   "morty@the-citadel.com",
		Roles:   []string{"editor"},
		Picture: "https://www.topaz.sh/assets/templates/citadel/img/Morty%20Smith.jpg",
	},
	"CiRmZDI2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs": {
		ID:      "summer@the-smiths.com",
		Name:    "Summer Smith",
		Email:   "summer@the-smiths.com",
		Roles:   []string{"editor"},
		Picture: "https://www.topaz.sh/assets/templates/citadel/img/Summer%20Smith.jpg",
	},
	"CiRmZDQ2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs": {
		ID:      "jerry@the-smiths.com",
		Name:    "Jerry Smith",
		Email:   "jerry@the-smiths.com",
		Roles:   []string{"viewer"},
		Picture: "https://www.topaz.sh/assets/templates/citadel/img/Jerry%20Smith.jpg",
	},
}
