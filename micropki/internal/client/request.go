package client

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "mime/multipart"
    "net/http"
    "os"
    "path/filepath"
)

type CertificateRequest struct {
    CSRPath   string
    Template  string
    CAURL     string
    OutCert   string
    APIKey    string
}

type APIResponse struct {
    Success bool   `json:"success"`
    Message string `json:"message,omitempty"`
    CertPEM string `json:"certificate,omitempty"`
}

// RequestCertificate отправляет CSR в CA и сохраняет полученный сертификат
func RequestCertificate(req *CertificateRequest) error {
    // Чтение CSR файла
    csrData, err := os.ReadFile(req.CSRPath)
    if err != nil {
        return fmt.Errorf("ошибка чтения CSR: %w", err)
    }
    
    // Подготовка multipart формы
    var buf bytes.Buffer
    writer := multipart.NewWriter(&buf)
    
    // Добавляем CSR файл
    part, err := writer.CreateFormFile("csr", filepath.Base(req.CSRPath))
    if err != nil {
        return fmt.Errorf("ошибка создания формы: %w", err)
    }
    if _, err := part.Write(csrData); err != nil {
        return fmt.Errorf("ошибка записи CSR: %w", err)
    }
    
    // Добавляем template
    if err := writer.WriteField("template", req.Template); err != nil {
        return fmt.Errorf("ошибка добавления template: %w", err)
    }
    
    writer.Close()
    
    // Создание HTTP запроса
    url := fmt.Sprintf("%s/request-cert", req.CAURL)
    httpReq, err := http.NewRequest("POST", url, &buf)
    if err != nil {
        return fmt.Errorf("ошибка создания запроса: %w", err)
    }
    httpReq.Header.Set("Content-Type", writer.FormDataContentType())
    
    if req.APIKey != "" {
        httpReq.Header.Set("X-API-Key", req.APIKey)
    }
    
    // Отправка запроса
    client := &http.Client{}
    resp, err := client.Do(httpReq)
    if err != nil {
        return fmt.Errorf("ошибка отправки запроса: %w", err)
    }
    defer resp.Body.Close()
    
    // Обработка ответа
    if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        
        // Пробуем распарсить JSON ошибку
        var apiErr APIResponse
        if err := json.Unmarshal(body, &apiErr); err == nil && apiErr.Message != "" {
            return fmt.Errorf("ошибка CA: %s", apiErr.Message)
        }
        
        return fmt.Errorf("ошибка HTTP %d: %s", resp.StatusCode, string(body))
    }
    
    // Сохранение сертификата
    certData, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("ошибка чтения ответа: %w", err)
    }
    
    if err := os.WriteFile(req.OutCert, certData, 0644); err != nil {
        return fmt.Errorf("ошибка сохранения сертификата: %w", err)
    }
    
    return nil
}