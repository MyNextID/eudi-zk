package main

// // base64UrlEncode encodes bytes to base64url format (RFC 4648 Section 5)
// // Base64url encoding: converts 3 bytes to 4 characters using URL-safe alphabet
// func base64UrlEncode(api frontend.API, input []uints.U8) []uints.U8 {
// 	// Base64url alphabet: A-Z, a-z, 0-9, -, _
// 	alphabet := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
//
// 	inputLen := len(input)
// 	// Calculate output length (4 chars per 3 bytes, no padding for base64url)
// 	outputLen := (inputLen*4 + 2) / 3
// 	output := make([]uints.U8, outputLen)
//
// 	outIdx := 0
//
// 	// Process input in 3-byte chunks
// 	for i := 0; i < inputLen; i += 3 {
// 		// Get up to 3 bytes
// 		b1 := input[i].Val
// 		var b2, b3 frontend.Variable
//
// 		if i+1 < inputLen {
// 			b2 = input[i+1].Val
// 		} else {
// 			b2 = frontend.Variable(0)
// 		}
//
// 		if i+2 < inputLen {
// 			b3 = input[i+2].Val
// 		} else {
// 			b3 = frontend.Variable(0)
// 		}
//
// 		// Combine 3 bytes into 24-bit value
// 		// val = (b1 << 16) | (b2 << 8) | b3
// 		val := api.Add(
// 			api.Mul(b1, 65536), // b1 << 16
// 			api.Add(
// 				api.Mul(b2, 256), // b2 << 8
// 				b3,
// 			),
// 		)
//
// 		// Extract 4 6-bit indices for base64 characters
// 		// idx1 = (val >> 18) & 0x3F
// 		idx1 := api.Div(val, 262144)             // val / 2^18
// 		idx1_masked := bitwiseAnd(api, idx1, 63) // & 0x3F
//
// 		// idx2 = (val >> 12) & 0x3F
// 		idx2 := api.Div(val, 4096)               // val / 2^12
// 		idx2_masked := bitwiseAnd(api, idx2, 63) // & 0x3F
//
// 		// idx3 = (val >> 6) & 0x3F
// 		idx3 := api.Div(val, 64)                 // val / 2^6
// 		idx3_masked := bitwiseAnd(api, idx3, 63) // & 0x3F
//
// 		// idx4 = val & 0x3F
// 		idx4_masked := bitwiseAnd(api, val, 63)
//
// 		// Convert indices to characters using lookup
// 		output[outIdx] = lookupBase64Char(api, idx1_masked, alphabet)
// 		outIdx++
//
// 		if outIdx < outputLen {
// 			output[outIdx] = lookupBase64Char(api, idx2_masked, alphabet)
// 			outIdx++
// 		}
//
// 		if i+1 < inputLen && outIdx < outputLen {
// 			output[outIdx] = lookupBase64Char(api, idx3_masked, alphabet)
// 			outIdx++
// 		}
//
// 		if i+2 < inputLen && outIdx < outputLen {
// 			output[outIdx] = lookupBase64Char(api, idx4_masked, alphabet)
// 			outIdx++
// 		}
// 	}
//
// 	return output
// }
//
