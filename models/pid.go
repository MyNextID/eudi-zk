package models

// EUDI Personal Identification Data (PID) data model proposal for SD-JWT VC
// format

// Address represents the resident address structure
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	Country       string `json:"country,omitempty"`
	Region        string `json:"region,omitempty"`
	Locality      string `json:"locality,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	HouseNumber   string `json:"house_number,omitempty"`
}

// PlaceOfBirth represents the birth place structure
type PlaceOfBirth struct {
	Locality string `json:"locality,omitempty"`
	Region   string `json:"region,omitempty"`
	Country  string `json:"country,omitempty"`
}

// PersonIdentificationData represents the complete PID structure
type PersonIdentificationData struct {
	// Base type - should be "urn:eudi:pid:1"
	VCT string `json:"vct"`

	// Public names - Table 7
	FamilyName      string        `json:"family_name,omitempty"`
	GivenName       string        `json:"given_name,omitempty"`
	BirthDate       string        `json:"birthdate,omitempty"` // ISO 8601-1, YYYY-MM-DD format
	PlaceOfBirth    *PlaceOfBirth `json:"place_of_birth,omitempty"`
	Nationalities   []string      `json:"nationalities,omitempty"`
	Address         *Address      `json:"address,omitempty"`
	BirthFamilyName string        `json:"birth_family_name,omitempty"`
	BirthGivenName  string        `json:"birth_given_name,omitempty"`
	Email           string        `json:"email,omitempty"`
	PhoneNumber     string        `json:"phone_number,omitempty"`
	Picture         string        `json:"picture,omitempty"` // data URL with base64-encoded JPEG

	// Private names - Table 8
	DateOfExpiry                 string `json:"date_of_expiry,omitempty"`
	DateOfIssuance               string `json:"date_of_issuance,omitempty"`
	PersonalAdministrativeNumber string `json:"personal_administrative_number,omitempty"`
	Sex                          int    `json:"sex,omitempty"` // Number type
	IssuingAuthority             string `json:"issuing_authority,omitempty"`
	IssuingCountry               string `json:"issuing_country,omitempty"`
	DocumentNumber               string `json:"document_number,omitempty"`
	IssuingJurisdiction          string `json:"issuing_jurisdiction,omitempty"`
	TrustAnchor                  string `json:"trust_anchor,omitempty"`
}

// GetDemoPID returns a fully populated demo PID for testing and examples
func GetDemoPID() *PersonIdentificationData {
	return &PersonIdentificationData{
		VCT:        "urn:eudi:pid:1",
		FamilyName: "Muller",
		GivenName:  "Erika",
		BirthDate:  "1985-03-15",
		PlaceOfBirth: &PlaceOfBirth{
			Locality: "Munich",
			Region:   "Bavaria",
			Country:  "DE",
		},
		Nationalities: []string{"DE", "AT"},
		Address: &Address{
			Formatted:     "Hauptstraße 123, 80331 München, Germany",
			Country:       "DE",
			Region:        "Bavaria",
			Locality:      "München",
			PostalCode:    "80331",
			StreetAddress: "Hauptstraße",
			HouseNumber:   "123",
		},
		BirthFamilyName:              "Schmidt",
		BirthGivenName:               "Erika",
		Email:                        "erika.muller@example.com",
		PhoneNumber:                  "+49-89-12345678",
		Picture:                      "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCwAA//2Q==",
		DateOfExpiry:                 "2030-12-31",
		DateOfIssuance:               "2020-01-15",
		PersonalAdministrativeNumber: "123456789012",
		Sex:                          2, // Female
		IssuingAuthority:             "Stadt München, Kreisverwaltungsreferat",
		IssuingCountry:               "DE",
		DocumentNumber:               "L01X00T47",
		IssuingJurisdiction:          "DE-BY",
		TrustAnchor:                  "urn:eudi:trust:anchor:de:bsi",
	}
}

// GetDemoPID returns a fully populated demo PID for testing and examples
func GetDemoPIDUnder18() *PersonIdentificationData {
	return &PersonIdentificationData{
		VCT:        "urn:eudi:pid:1",
		FamilyName: "Muller",
		GivenName:  "Erika",
		BirthDate:  "2024-03-15",
		PlaceOfBirth: &PlaceOfBirth{
			Locality: "Munich",
			Region:   "Bavaria",
			Country:  "DE",
		},
		Nationalities: []string{"DE", "AT"},
		Address: &Address{
			Formatted:     "Hauptstraße 123, 80331 München, Germany",
			Country:       "DE",
			Region:        "Bavaria",
			Locality:      "München",
			PostalCode:    "80331",
			StreetAddress: "Hauptstraße",
			HouseNumber:   "123",
		},
		BirthFamilyName:              "Schmidt",
		BirthGivenName:               "Erika",
		Email:                        "erika.muller@example.com",
		PhoneNumber:                  "+49-89-12345678",
		Picture:                      "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCwAA//2Q==",
		DateOfExpiry:                 "2030-12-31",
		DateOfIssuance:               "2020-01-15",
		PersonalAdministrativeNumber: "123456789012",
		Sex:                          2, // Female
		IssuingAuthority:             "Stadt München, Kreisverwaltungsreferat",
		IssuingCountry:               "DE",
		DocumentNumber:               "L01X00T47",
		IssuingJurisdiction:          "DE-BY",
		TrustAnchor:                  "urn:eudi:trust:anchor:de:bsi",
	}
}
