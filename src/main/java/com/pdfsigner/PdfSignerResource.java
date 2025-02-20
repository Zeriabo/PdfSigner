package com.pdfsigner;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.File;

import jakarta.inject.Inject;

@Path("/signpdf")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.MULTIPART_FORM_DATA)
public class PdfSignerResource {

    @Inject
    PdfSignerService pdfSignerService;

    @POST
    @Path("/sign")
    public Response signPdf(@FormParam("file") File file, @FormParam("name") String name,
            @FormParam("reason") String reason, @FormParam("location") String location)
            throws Exception {
        File signedPdfPath = pdfSignerService.signPdf(file, name, reason, location);
        return Response.ok().entity("Signed PDF: " + signedPdfPath).build();
    }
}
