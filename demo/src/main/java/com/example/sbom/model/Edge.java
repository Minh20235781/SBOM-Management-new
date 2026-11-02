package com.example.sbom.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Edge {
    private String from;
    private String to;
    private String type; // runtime | dev | optional | third-party
}

