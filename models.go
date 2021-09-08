package main

///Todo: Edit to feet the needs of the DB
// NOTE: These structs are mostly for the expected JSON format, not necessarily the
// database schema.
// 'omitempty' indicates not to use default values if omitted, e.g. do not use
// 0 for a missing int

type WellbeingRecord struct {
	PostCode         string  `json:"postCode"`
	WeeklySteps      uint    `json:"weeklySteps,omitempty"`
	WellbeingScore   float64 `json:"wellbeingScore,omitempty"`
	sputumColour     float64 `json:"sputumColour,omitempty"`
	mrcDyspnoeaScale float64 `json:"mrcDyspnoeaScale,omitempty"`
	speechRateTest   float64 `json:"speechRateTest,omitempty"`
	testDuration     float64 `json:"testDuration,omitempty"`
	//ErrorRate			int    `json:"errorRate,omitempty"`
	SupportCode string `json:"supportCode"`
	DateSent    string `json:"date_sent,omitempty"`
	AudioUrl    string `json:"audioUrl"`
}

type User struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"` // sent unhashed
}

type NewMessageJSON struct {
	Identifier_from string      `json:"identifier_from"`
	Password        string      `json:"password"` // verifies identifier_from
	Identifier_to   string      `json:"identifier_to"`
	Data            interface{} `json:"data"`
}
