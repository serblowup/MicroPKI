package validation

import (
    "crypto/x509"
    "fmt"
)

type ChainBuilder struct {
    trustedRoots []*x509.Certificate
    intermediates []*x509.Certificate
}

func NewChainBuilder() *ChainBuilder {
    return &ChainBuilder{
        trustedRoots: make([]*x509.Certificate, 0),
        intermediates: make([]*x509.Certificate, 0),
    }
}

func (cb *ChainBuilder) AddTrustedRoot(cert *x509.Certificate) {
    cb.trustedRoots = append(cb.trustedRoots, cert)
}

func (cb *ChainBuilder) AddIntermediate(cert *x509.Certificate) {
    cb.intermediates = append(cb.intermediates, cert)
}

func (cb *ChainBuilder) BuildChain(leaf *x509.Certificate) ([]*x509.Certificate, error) {
    for _, root := range cb.trustedRoots {
        if leaf.Equal(root) {
            return []*x509.Certificate{leaf}, nil
        }
    }
    
    // Рекурсивный поиск пути
    path, err := cb.findPath(leaf, []*x509.Certificate{leaf})
    if err != nil {
        return nil, fmt.Errorf("не удалось построить цепочку: %w", err)
    }
    
    return path, nil
}

func (cb *ChainBuilder) findPath(current *x509.Certificate, visited []*x509.Certificate) ([]*x509.Certificate, error) {
    for _, root := range cb.trustedRoots {
        if err := current.CheckSignatureFrom(root); err == nil {
            return append(visited, root), nil
        }
    }
    
    // Ищем среди промежуточных сертификатов
    var foundPaths [][]*x509.Certificate
    
    for _, intermediate := range cb.intermediates {
        // Проверяем подпись
        if err := current.CheckSignatureFrom(intermediate); err != nil {
            continue
        }
        
        // Проверяем, что не зациклились
        if contains(visited, intermediate) {
            continue
        }
        
        // Рекурсивно ищем дальше
        newVisited := append(visited, intermediate)
        subPath, err := cb.findPath(intermediate, newVisited)
        if err == nil {
            foundPaths = append(foundPaths, subPath)
        }
    }
    
    if len(foundPaths) == 0 {
        return nil, fmt.Errorf("путь не найден")
    }
    
    // Выбираем кратчайший путь
    shortest := foundPaths[0]
    for _, path := range foundPaths[1:] {
        if len(path) < len(shortest) {
            shortest = path
        }
    }
    
    return shortest, nil
}

func contains(certs []*x509.Certificate, cert *x509.Certificate) bool {
    for _, c := range certs {
        if c.Equal(cert) {
            return true
        }
    }
    return false
}