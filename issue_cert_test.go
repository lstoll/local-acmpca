package main

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca/types"
)

func TestParseValidity(t *testing.T) {
	baseTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name        string
		validity    types.Validity
		startTime   time.Time
		expected    time.Time
		expectError bool
	}{
		// ValidityPeriodTypeEndDate tests
		{
			name: "EndDate - UTCTime format - year >= 50 (19YY)",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeEndDate,
				Value: aws.Int64(750722201704), // 75-07-22 20:17:04 -> 1975-07-22 20:17:04
			},
			startTime:   baseTime,
			expected:    time.Date(1975, 7, 22, 20, 17, 4, 0, time.UTC),
			expectError: false,
		},
		{
			name: "EndDate - UTCTime format - year < 50 (20YY)",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeEndDate,
				Value: aws.Int64(250722201704), // 25-07-22 20:17:04 -> 2025-07-22 20:17:04
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 7, 22, 20, 17, 4, 0, time.UTC),
			expectError: false,
		},
		{
			name: "EndDate - GeneralizedTime format",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeEndDate,
				Value: aws.Int64(20250722201704), // 2025-07-22 20:17:04
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 7, 22, 20, 17, 4, 0, time.UTC),
			expectError: false,
		},
		{
			name: "EndDate - Invalid format (13 digits)",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeEndDate,
				Value: aws.Int64(1234567890123), // Invalid 13-digit format
			},
			startTime:   baseTime,
			expected:    time.Time{},
			expectError: true,
		},

		// ValidityPeriodTypeAbsolute tests
		{
			name: "Absolute - Unix timestamp",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeAbsolute,
				Value: aws.Int64(1705314600), // 2024-01-15 10:30:00 UTC
			},
			startTime:   baseTime,
			expected:    time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},
		{
			name: "Absolute - Future timestamp",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeAbsolute,
				Value: aws.Int64(1735734600), // 2025-01-01 12:30:00 UTC
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 1, 1, 12, 30, 0, 0, time.UTC),
			expectError: false,
		},

		// ValidityPeriodTypeDays tests
		{
			name: "Days - 1 day",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeDays,
				Value: aws.Int64(1),
			},
			startTime:   baseTime,
			expected:    time.Date(2024, 1, 16, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},
		{
			name: "Days - 365 days",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeDays,
				Value: aws.Int64(365),
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 1, 14, 10, 30, 0, 0, time.UTC), // 2024 is leap year, so 365 days = 2025-01-14
			expectError: false,
		},
		{
			name: "Days - Leap year handling",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeDays,
				Value: aws.Int64(366), // 2024 is a leap year
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC), // 366 days from 2024-01-15 = 2025-01-15
			expectError: false,
		},

		// ValidityPeriodTypeMonths tests
		{
			name: "Months - 1 month",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeMonths,
				Value: aws.Int64(1),
			},
			startTime:   baseTime,
			expected:    time.Date(2024, 2, 15, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},
		{
			name: "Months - 12 months",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeMonths,
				Value: aws.Int64(12),
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},

		// ValidityPeriodTypeYears tests
		{
			name: "Years - 1 year",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeYears,
				Value: aws.Int64(1),
			},
			startTime:   baseTime,
			expected:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},
		{
			name: "Years - 10 years",
			validity: types.Validity{
				Type:  types.ValidityPeriodTypeYears,
				Value: aws.Int64(10),
			},
			startTime:   baseTime,
			expected:    time.Date(2034, 1, 15, 10, 30, 0, 0, time.UTC),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseValidity(tt.startTime, tt.validity)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if !result.Equal(tt.expected) {
				t.Errorf("parseValidity() = %v, want %v", result, tt.expected)
			}
		})
	}
}
